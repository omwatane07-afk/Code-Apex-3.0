/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: ["class", '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        app: "var(--bg-app)",
        surface: "var(--bg-surface)",
        rule: "var(--border-rule)",
        main: "var(--text-main)",
        muted: "var(--text-muted)",
        primary: {
          DEFAULT: "var(--primary)",
          hover: "var(--primary-hover)",
          fg: "var(--primary-fg)",
        },
        status: {
          ok: "var(--status-ok)",
          due_soon: "var(--status-due-soon)",
          critical: "var(--status-critical)",
          breached: "var(--status-breached)",
          info: "var(--status-info)",
        },
        cyber: {
          void: "#050508",
          panel: "#0A0D14",
          hover: "#111722",
          border: "#1A2332",
          green: "#00FF66",
          cyan: "#00E5FF",
          blue: "#0088FF",
          red: "#FF1E42",
          white: "#F0F6FC",
          slate: "#8B9BB4",
        },
      },
      borderRadius: {
        control: "var(--radius-control)",
        segment: "var(--radius-segment)",
        row: "var(--radius-row)",
      },
      fontFamily: {
        sans: ["var(--font-ui)"],
        mono: ["var(--font-mono)"],
      },
    },
  },
  plugins: [],
}
