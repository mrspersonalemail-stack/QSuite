import pytest

from qsuite.game import minecraft_logs, varint


def test_player_log_feed_excludes_ip_connections_security_and_paths(tmp_path, settings):
    root = tmp_path / "game"
    (root / "logs").mkdir(parents=True)
    (root / "logs/latest.log").write_text(
        "[12:34:56] [Server thread/INFO]: PlayerOne joined the game\n"
        "[12:34:57] [Server thread/INFO]: <PlayerOne> Hello everyone\n"
        "[12:34:58] [Server thread/INFO]: PlayerOne[/192.0.2.1:1234] logged in with entity id 4\n"
        "[12:34:59] [Server thread/ERROR]: Configuration /etc/ssh/sshd_config\n"
        "[12:35:00] [Server thread/INFO]: <PlayerOne> My address is 192.0.2.1 and path /srv/private/world\n"
    )
    settings = settings.model_copy(
        update={"integration": settings.integration.model_copy(update={"minecraft_root": str(root)})}
    )
    output = minecraft_logs(settings)
    assert len(output["lines"]) == 3
    assert (
        "192.0.2.1" not in str(output) and "/etc/ssh" not in str(output) and "/srv/private" not in str(output)
    )


@pytest.mark.parametrize("part", ["logs", "latest.log"])
def test_log_symlinks_cannot_redirect_root_reads(tmp_path, settings, part):
    root = tmp_path / "game"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("[12:34:56] [Server thread/INFO]: <Secret> private data\n")
    if part == "logs":
        (root / "logs").symlink_to(outside, target_is_directory=True)
    else:
        (root / "logs").mkdir()
        (root / "logs/latest.log").symlink_to(outside / "secret")
    configured = settings.model_copy(
        update={"integration": settings.integration.model_copy(update={"minecraft_root": str(root)})}
    )
    assert minecraft_logs(configured)["lines"] == []


def test_status_varint_bounded_negative_protocol_encoding():
    assert varint(-1) == b"\xff\xff\xff\xff\x0f"


def test_symlink_in_game_root_ancestor_is_rejected(tmp_path, settings):
    outside = tmp_path / "outside"
    (outside / "game/logs").mkdir(parents=True)
    (outside / "game/logs/latest.log").write_text("[12:34:56] [Server thread/INFO]: <Secret> private\n")
    (tmp_path / "alias").symlink_to(outside, target_is_directory=True)
    configured = settings.model_copy(
        update={
            "integration": settings.integration.model_copy(
                update={"minecraft_root": str(tmp_path / "alias/game")}
            )
        }
    )
    assert minecraft_logs(configured)["lines"] == []
