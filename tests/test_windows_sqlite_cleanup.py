"""Portable resource-lifetime contracts for Windows SQLite file sharing.

Windows will not remove a temporary database while another process-local
SQLite handle still references it.  These checks deliberately close both
STM's archive handle and every diagnostic raw SQLite handle before unlink.
"""

from contextlib import closing
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from stm.archive import ArchiveScope, ConversationArchive


SCOPE = ArchiveScope("synthetic", "owner", "vera")


class WindowsSqliteHandleLifetimeTests(unittest.TestCase):
    def test_archive_close_releases_file_for_removal(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "conversation.sqlite"
            archive = ConversationArchive(str(path), authorize=lambda *_: True)
            try:
                original = archive.append_turn(
                    "host", SCOPE, conversation_id="local-demo", role="user",
                    content="A synthetic violet paperclip", source="test:turn-1",
                )
                self.assertEqual(len(archive.search(
                    "host", SCOPE, "violet",
                    privacy_scopes=frozenset({"private"}),
                )), 1)
                archive.correct("host", SCOPE, original.turn_id,
                                "A synthetic orange paperclip")
            finally:
                archive.close()
            # Unlike POSIX, Windows won't let this succeed if the SQLite file
            # handle remains open.  Windows CI exercises the native behavior.
            path.unlink()
            self.assertFalse(path.exists())

    def test_raw_sqlite_diagnostic_handle_is_explicitly_closed(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "raw.sqlite"
            with closing(sqlite3.connect(path)) as connection:
                with connection:
                    connection.execute("CREATE TABLE sample(value INTEGER NOT NULL)")
                    connection.execute("INSERT INTO sample(value) VALUES (1)")
                self.assertEqual(connection.execute(
                    "SELECT value FROM sample"
                ).fetchone(), (1,))
            path.unlink()
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
