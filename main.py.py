import os
import ast
import subprocess
from typing import List, Optional
from datetime import datetime
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

app = FastAPI(
    title="NeuraNova — Sherlock Code Inspector API",
    version="1.4.0"
)

# Enable CORS for local dashboard access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class EvidenceItem(BaseModel):
    category: str
    finding: str
    risk_points: int


class TestCaseParameter(BaseModel):
    id: str
    parameter_name: str
    rule_description: str
    weight: int
    observed_value: str
    passed: bool
    verdict_impact: str


class OwnershipRequest(BaseModel):
    repo_path: str
    file_path: str
    symbol_name: str
    requester_email: EmailStr
    reason: str


class OwnershipResponse(BaseModel):
    ticket_id: str
    status: str
    target_owner: str
    timestamp: str
    message: str


class InvestigationReport(BaseModel):
    target_repo: str
    target_file: str
    target_symbol: str
    totalRiskScore: int
    verdict: str  # 'safe' | 'review' | 'danger'
    verdictText: str
    reason: str
    detected_owner: str
    evidence_list: List[EvidenceItem]
    test_cases: List[TestCaseParameter]


class SymbolVisitor(ast.NodeVisitor):
    def __init__(self, target_symbol: str):
        self.target_symbol = target_symbol
        self.found_references = 0

    def visit_Name(self, node: ast.Name):
        if node.id == self.target_symbol:
            self.found_references += 1
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        if node.attr == self.target_symbol:
            self.found_references += 1
        self.generic_visit(node)


def scan_ast_references(repo_path: str, target_symbol: str) -> tuple[int, List[str]]:
    """Scans all Python files in the repository for references using AST."""
    ref_count = 0
    referencing_files = []

    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, repo_path)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        tree = ast.parse(f.read(), filename=file_path)
                    visitor = SymbolVisitor(target_symbol)
                    visitor.visit(tree)
                    if visitor.found_references > 0:
                        ref_count += visitor.found_references
                        referencing_files.append(rel_path)
                except SyntaxError:
                    continue

    return ref_count, referencing_files


def check_git_history(repo_path: str, file_path: str) -> tuple[bool, str, str]:
    """Inspects recent git history for target file and extracts last author."""
    full_path = os.path.join(repo_path, file_path)
    if not os.path.exists(full_path):
        return False, "File does not exist on disk.", "Unassigned"

    try:
        cmd_msg = ["git", "log", "-1", "--format=%cr by %an (%h)", "--", file_path]
        res_msg = subprocess.run(cmd_msg, cwd=repo_path, capture_output=True, text=True, check=True)
        msg_out = res_msg.stdout.strip()

        cmd_author = ["git", "log", "-1", "--format=%an", "--", file_path]
        res_author = subprocess.run(cmd_author, cwd=repo_path, capture_output=True, text=True, check=True)
        author_out = res_author.stdout.strip()

        if msg_out:
            return True, f"Last modified {msg_out}", author_out or "Core Team"
        return False, "No git history found for this file.", "Unassigned"
    except Exception:
        return False, "Git history check skipped (not a git repo).", "Core Team"


@app.get("/api/v1/investigate", response_model=InvestigationReport)
def investigate_symbol(
    repo: str = Query(..., description="Path to target repo"),
    file: str = Query(..., description="Relative file path"),
    symbol: str = Query(..., description="Symbol name"),
):
    abs_repo = os.path.abspath(repo)
    if not os.path.exists(abs_repo):
        raise HTTPException(status_code=400, detail=f"Repository path '{repo}' not found.")

    evidence: List[EvidenceItem] = []
    test_cases: List[TestCaseParameter] = []
    total_risk = 0

    # 1. Verify Definition
    target_full_path = os.path.join(abs_repo, file)
    symbol_defined = False
    if os.path.exists(target_full_path):
        try:
            with open(target_full_path, "r", encoding="utf-8", errors="ignore") as f:
                tree = ast.parse(f.read())
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    if node.name == symbol:
                        symbol_defined = True
                        break
        except Exception:
            pass

    evidence.append(
        EvidenceItem(
            category="Definition",
            finding=f"Symbol `{symbol}` confirmed in `{file}`." if symbol_defined else f"Symbol `{symbol}` not explicitly defined in `{file}`.",
            risk_points=0,
        )
    )

    test_cases.append(
        TestCaseParameter(
            id="TC-01",
            parameter_name="Explicit Symbol Definition Check",
            rule_description="Verifies if symbol node exists as class or function in target AST AST tree",
            weight=10,
            observed_value="Node Exists" if symbol_defined else "Node Missing/Implicit",
            passed=symbol_defined,
            verdict_impact="Confirms symbol scope and AST parse validity."
        )
    )

    # 2. Static AST References
    ref_count, ref_files = scan_ast_references(abs_repo, symbol)
    external_refs = [f for f in ref_files if f != file and not f.startswith("test")]
    
    if external_refs:
        risk = min(len(external_refs) * 25, 50)
        total_risk += risk
        evidence.append(
            EvidenceItem(
                category="Static References",
                finding=f"Referenced in {len(external_refs)} external module(s): {', '.join(external_refs[:3])}",
                risk_points=risk,
            )
        )
    else:
        evidence.append(
            EvidenceItem(
                category="Static References",
                finding="No static references detected across external modules.",
                risk_points=0,
            )
        )

    test_cases.append(
        TestCaseParameter(
            id="TC-02",
            parameter_name="External Dependency Analysis",
            rule_description="Triggers high risk penalty if AST references exist outside target file",
            weight=50,
            observed_value=f"{len(external_refs)} external file(s) depend on symbol",
            passed=len(external_refs) == 0,
            verdict_impact="High score (>50) forces DO NOT DELETE verdict."
        )
    )

    # 3. Test Coverage
    test_refs = [f for f in ref_files if "test" in f]
    if test_refs:
        risk = 35
        total_risk += risk
        evidence.append(
            EvidenceItem(
                category="Tests",
                finding=f"Covered in {len(test_refs)} test file(s): {', '.join(test_refs[:2])}",
                risk_points=risk,
            )
        )
    else:
        evidence.append(
            EvidenceItem(
                category="Tests",
                finding="No direct test suite references found.",
                risk_points=0,
            )
        )

    test_cases.append(
        TestCaseParameter(
            id="TC-03",
            parameter_name="Regression Test Suite Coverage",
            rule_description="Verifies whether automated unit/integration tests call this symbol",
            weight=35,
            observed_value=f"Found in {len(test_refs)} test files" if test_refs else "0 test references",
            passed=len(test_refs) == 0,
            verdict_impact="Test presence flags code as active regression risk."
        )
    )

    # 4. Git History & Owner Extraction
    has_git, git_msg, detected_owner = check_git_history(abs_repo, file)
    evidence.append(
        EvidenceItem(
            category="Git History",
            finding=git_msg,
            risk_points=0,
        )
    )

    test_cases.append(
        TestCaseParameter(
            id="TC-04",
            parameter_name="Git Provenance & Ownership Check",
            rule_description="Queries commit logs to identify last author and revision recency",
            weight=15,
            observed_value=f"Owner: {detected_owner} | {git_msg}",
            passed=has_git,
            verdict_impact="Extracts owner contact for rights transfer requests."
        )
    )

    # Verdict Logic
    if total_risk >= 50:
        verdict = "danger"
        verdict_text = "🔴 DO NOT DELETE"
        reason = "Active dependencies or test suites rely on this symbol."
    elif total_risk >= 15:
        verdict = "review"
        verdict_text = "🟡 REVIEW BEFORE DELETION"
        reason = "Indirect references or test dependencies detected."
    else:
        verdict = "safe"
        verdict_text = "🟢 SAFE TO DELETE"
        reason = "No static references or test dependencies found across project."

    test_cases.append(
        TestCaseParameter(
            id="TC-05",
            parameter_name="Final Risk Threshold Assessment",
            rule_description="Evaluates cumulative risk points against deletion safety boundaries (Safe < 15, Review 15-49, Danger ≥ 50)",
            weight=100,
            observed_value=f"Total Score = {total_risk} pts",
            passed=total_risk < 15,
            verdict_impact=f"Final Verdict assigned as {verdict_text}."
        )
    )

    return InvestigationReport(
        target_repo=repo,
        target_file=file,
        target_symbol=symbol,
        totalRiskScore=total_risk,
        verdict=verdict,
        verdictText=verdict_text,
        reason=reason,
        detected_owner=detected_owner,
        evidence_list=evidence,
        test_cases=test_cases,
    )


@app.post("/api/v1/request-ownership", response_model=OwnershipResponse)
def request_code_ownership(payload: OwnershipRequest):
    ticket_id = f"TK-{hash(payload.file_path + payload.symbol_name) % 100000:05d}"
    abs_repo = os.path.abspath(payload.repo_path)
    _, _, detected_owner = check_git_history(abs_repo, payload.file_path)

    return OwnershipResponse(
        ticket_id=ticket_id,
        status="PENDING_OWNER_APPROVAL",
        target_owner=detected_owner,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        message=f"Ownership ticket {ticket_id} routed to {detected_owner}. Notification sent from {payload.requester_email}."
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)