"""Mixed-Integer Linear Programming (MILP) cybersecurity capital optimization engine."""

from datetime import UTC, datetime
from typing import Any

import numpy as np
from scipy.optimize import Bounds, LinearConstraint, milp  # type: ignore[import-untyped]
from sqlalchemy.orm import Session

from cyberq.audit.chain import AuditService
from cyberq.optimizer.models import OptimizationResult, SecurityControl

DEFAULT_BANK_CONTROLS: list[SecurityControl] = [
    SecurityControl(
        control_id="CTRL-PAM-01",
        name="CyberArk / BeyondTrust Privileged Access Hardening",
        category="identity",
        cost_lakhs=35.0,
        risk_reduction_lakhs=120.0,
    ),
    SecurityControl(
        control_id="CTRL-EDR-02",
        name="CrowdStrike Falcon Enterprise EDR Deployment",
        category="endpoint",
        cost_lakhs=45.0,
        risk_reduction_lakhs=145.0,
        dependencies=["CTRL-PAM-01"],
    ),
    SecurityControl(
        control_id="CTRL-DAM-03",
        name="Imperva SecureSphere Database Activity Monitoring",
        category="database",
        cost_lakhs=40.0,
        risk_reduction_lakhs=110.0,
    ),
    SecurityControl(
        control_id="CTRL-HSM-04",
        name="Thales Luna HSM Cryptographic Root-of-Trust",
        category="cryptography",
        cost_lakhs=50.0,
        risk_reduction_lakhs=160.0,
    ),
    SecurityControl(
        control_id="CTRL-MICROSEG-05",
        name="Illumio Zero-Trust Network Microsegmentation",
        category="network",
        cost_lakhs=60.0,
        risk_reduction_lakhs=190.0,
        mutually_exclusive_with=["CTRL-LEGACY-VLAN-07"],
    ),
    SecurityControl(
        control_id="CTRL-AUTO-PATCH-06",
        name="Automated Vulnerability & Kernel Patching Pipeline",
        category="automation",
        cost_lakhs=25.0,
        risk_reduction_lakhs=85.0,
    ),
    SecurityControl(
        control_id="CTRL-LEGACY-VLAN-07",
        name="Legacy Subnet ACL Firewall Segmentation",
        category="network",
        cost_lakhs=15.0,
        risk_reduction_lakhs=40.0,
        mutually_exclusive_with=["CTRL-MICROSEG-05"],
    ),
]


class CapitalOptimizer:
    """MILP solver for optimal cybersecurity capital investment."""

    @classmethod
    def _solve_milp_core(
        cls,
        candidate_controls: list[SecurityControl],
        budget_cap_lakhs: float,
    ) -> tuple[list[str], float, float, str]:
        """Core solver using SciPy HiGHS Mixed-Integer Linear Programming."""
        n = len(candidate_controls)
        ctrl_indices = {c.control_id: i for i, c in enumerate(candidate_controls)}

        # Objective: Maximize sum(risk_reduction * x_j) => Minimize -risk_reduction
        c_obj = np.array([-c.risk_reduction_lakhs for c in candidate_controls], dtype=np.float64)

        rows: list[list[float]] = []
        upper_bounds: list[float] = []

        # 1. Budget constraint: sum(cost * x_j) <= budget_cap
        cost_row = [c.cost_lakhs for c in candidate_controls]
        rows.append(cost_row)
        upper_bounds.append(budget_cap_lakhs)

        # 2. Dependency constraints: for each prereq d of j: x_j - x_d <= 0
        for ctrl in candidate_controls:
            j_idx = ctrl_indices[ctrl.control_id]
            for prereq_id in ctrl.dependencies:
                if prereq_id in ctrl_indices:
                    d_idx = ctrl_indices[prereq_id]
                    dep_row = [0.0] * n
                    dep_row[j_idx] = 1.0
                    dep_row[d_idx] = -1.0
                    rows.append(dep_row)
                    upper_bounds.append(0.0)

        # 3. Mutual exclusivity constraints: x_j + x_m <= 1
        seen_mutex: set[tuple[str, str]] = set()
        for ctrl in candidate_controls:
            j_idx = ctrl_indices[ctrl.control_id]
            for mutex_id in ctrl.mutually_exclusive_with:
                if mutex_id in ctrl_indices:
                    pair = (min(ctrl.control_id, mutex_id), max(ctrl.control_id, mutex_id))
                    if pair not in seen_mutex:
                        seen_mutex.add(pair)
                        m_idx = ctrl_indices[mutex_id]
                        mutex_row = [0.0] * n
                        mutex_row[j_idx] = 1.0
                        mutex_row[m_idx] = 1.0
                        rows.append(mutex_row)
                        upper_bounds.append(1.0)

        a_mat = np.array(rows, dtype=np.float64)
        b_u = np.array(upper_bounds, dtype=np.float64)
        b_l = np.full_like(b_u, -np.inf)

        constraints = LinearConstraint(a_mat, b_l, b_u)
        bounds = Bounds(0.0, 1.0)
        integrality = np.ones(n, dtype=int)  # 1 indicates integer (binary) variables

        res = milp(c=c_obj, constraints=constraints, bounds=bounds, integrality=integrality)

        status_str = "Optimal" if res.success else ("Infeasible" if res.status == 2 else "Feasible")
        selected_ids: list[str] = []
        actual_cost = 0.0
        achieved_reduction = 0.0

        if res.x is not None:
            for i, val in enumerate(res.x):
                if val > 0.5:
                    ctrl = candidate_controls[i]
                    selected_ids.append(ctrl.control_id)
                    actual_cost += ctrl.cost_lakhs
                    achieved_reduction += ctrl.risk_reduction_lakhs

        return selected_ids, actual_cost, achieved_reduction, status_str

    @classmethod
    def solve_allocation(
        cls,
        budget_cap_lakhs: float,
        controls: list[SecurityControl] | None = None,
        session: Session | None = None,
        audit: AuditService | None = None,
        actor_id: str = "SYSTEM_CISO",
        actor_role: str = "ciso",
    ) -> OptimizationResult:
        """Solves optimal control selection maximizing risk reduction under budget cap and constraints."""
        candidate_controls = controls if (controls and len(controls) > 0) else DEFAULT_BANK_CONTROLS
        ctrl_map = {c.control_id: c for c in candidate_controls}

        selected_ids, total_cost, total_risk_red, solver_status = cls._solve_milp_core(
            candidate_controls, budget_cap_lakhs
        )

        selected_objs = [ctrl_map[cid] for cid in selected_ids if cid in ctrl_map]
        roi_ratio = (total_risk_red / total_cost) if total_cost > 0.0 else 0.0

        # Compute Pareto Frontier Curve (from 0.2 to 2.0x budget in 10 steps)
        pareto_points = cls._compute_pareto_frontier(candidate_controls, budget_cap_lakhs)

        res = OptimizationResult(
            budget_cap_lakhs=budget_cap_lakhs,
            selected_control_ids=selected_ids,
            selected_controls=selected_objs,
            total_cost_lakhs=round(total_cost, 2),
            total_cost_crores=round(total_cost / 100.0, 4),
            total_risk_reduction_lakhs=round(total_risk_red, 2),
            total_risk_reduction_crores=round(total_risk_red / 100.0, 4),
            roi_ratio=round(roi_ratio, 2),
            solver_status=solver_status,
            pareto_frontier=pareto_points,
        )

        if audit and session:
            audit.record_event(
                session=session,
                actor_id=actor_id,
                actor_role=actor_role,
                action="optimizer:solve",
                entity_type="capital_optimizer",
                entity_id=f"OPT-{int(budget_cap_lakhs)}",
                client_ip="127.0.0.1",
                request_id=f"req-opt-{int(datetime.now(UTC).timestamp())}",
                after_state={
                    "budget_cap_lakhs": budget_cap_lakhs,
                    "selected_controls": selected_ids,
                    "total_risk_reduction_lakhs": res.total_risk_reduction_lakhs,
                },
            )

        return res

    @classmethod
    def _compute_pareto_frontier(
        cls,
        candidate_controls: list[SecurityControl],
        base_budget: float,
    ) -> list[dict[str, Any]]:
        """Calculates Pareto-optimal frontier curve points across budget multipliers."""
        multipliers = [0.2, 0.4, 0.6, 0.8, 1.0, 1.2, 1.4, 1.6, 1.8, 2.0]
        points: list[dict[str, Any]] = []

        for m in multipliers:
            b_val = round(base_budget * m, 2)
            sel_ids, act_cost, ach_red, _ = cls._solve_milp_core(candidate_controls, b_val)
            points.append({
                "budget_cap_lakhs": b_val,
                "actual_cost_lakhs": round(act_cost, 2),
                "risk_reduction_lakhs": round(ach_red, 2),
                "risk_reduction_crores": round(ach_red / 100.0, 4),
                "selected_controls_count": len(sel_ids),
            })

        return points
