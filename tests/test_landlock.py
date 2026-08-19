import subprocess, sys, json

LANDLOCK_HELPER = "app/runtime/sandbox_manager/landlock_worker.py"

def test_landlock_allows_authorized_read(tmp_path):
    d = tmp_path / "allowed"; d.mkdir()
    (d / "ok.txt").write_text("visible")
    result = subprocess.run(
        [sys.executable, LANDLOCK_HELPER, json.dumps({"mode": "read", "path": str(d / "ok.txt")})],
        capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert result.stdout == "visible"

def test_landlock_helper_denies_when_run_against_a_symlink_escape(tmp_path):
    """Défense en profondeur : même si un chemin passé au helper pointe, via un
    symlink, hors du dossier réellement accordé, Landlock bloque au niveau noyau."""
    allowed = tmp_path / "allowed"; allowed.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    escape_link = allowed / "escape"
    escape_link.symlink_to(outside) 
    #symlink cree un escape vers un autre link que linux va suivre : 
    #allowed/
    #├── file.txt
    #└── escape ─────→ /tmp/outside.txt
    result = subprocess.run(
        [sys.executable, LANDLOCK_HELPER, json.dumps({"mode": "read", "path": str(escape_link)})],
        capture_output=True, text=True,
    )
    assert result.returncode != 0  # bloqué : la cible réelle du lien est hors du dossier accordé