from typer.testing import CliRunner

from severance.cli import main
from severance.models import Finding


def test_investigate_reads_finding_file(tmp_path, monkeypatch):
    finding = Finding(
        id="file-test",
        kind="overly_permissive",
        resource_name="s3:PutObject on arn:aws:s3:::example/object",
        description="offline assessment",
    )
    path = tmp_path / "finding.json"
    path.write_text(finding.model_dump_json())
    seen = []
    monkeypatch.setattr(main, "_investigate", lambda f, *args: seen.append(f))
    result = CliRunner().invoke(main.app, ["investigate", "--finding-file", str(path)])
    assert result.exit_code == 0, result.output
    assert seen == [finding]


def test_investigate_rejects_ambiguous_inputs(tmp_path):
    path = tmp_path / "finding.json"
    path.write_text("{}")
    result = CliRunner().invoke(
        main.app, ["investigate", "--finding-file", str(path), "--scenario", "public_bucket"]
    )
    assert result.exit_code == 2
    assert "exactly one" in result.output
