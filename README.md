#  NeuraNova — Sherlock Code Inspector
Automated Dead Code Analysis, Risk Matrix &amp; Ownership Request Platform to make maintenance of software easier..

NeuraNova (Sherlock Code Inspector) is an enterprise-grade developer tool designed to safely identify dead or deprecated code, evaluate deletion risks through Abstract Syntax Tree (AST) analysis, and streamline code ownership governance across engineering teams.

---

## Key Features

* ** AST Static Analysis Engine:** Parses Python source files using standard `ast.parse` trees to verify symbol scope, definitions, and cross-module function/class references.

* ** Evaluation Test Cases Matrix:** Provides complete transparency into the verdict generation engine by displaying explicit test criteria, weights, rule parameters, and pass/fail statuses in an interactive modal.

* ** Visual Risk Impact Vector Map:** Renders an interactive Chart.js radar graph mapping dependency density, test coverage, symbol scope, and overall risk impact.

* ** Automated Code Ownership & Rights Portal:** Queries `git log` commit history to identify code authors/owners and provides a built-in ticket routing system to request ownership transfer or deletion approval.

* ** One-Click Sample Presets:** Includes pre-configured test scenarios for quick evaluation and demonstration during hackathon judging.
---

##  Project Architecture & File Structure

```text
sherlock-code-inspector/
├── main.py              # FastAPI Backend (AST Engine, Risk Calculation & Git Provenance)
├── index.html           # Tailwind CSS & Alpine.js Dashboard (Radar Graph & Test Matrix)
├── requirements.txt     # Python Dependencies
├── .gitignore           # Git Exclusion Rules
└── README.md            # Project Documentation
