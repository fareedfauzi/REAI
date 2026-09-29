from reai.utils.hashing import hash_file


def test_hash_file_known_values(tmp_path):
    sample = tmp_path / "abc.bin"
    sample.write_bytes(b"abc")

    hashes = hash_file(sample)

    assert hashes.size == 3
    assert hashes.md5 == "900150983cd24fb0d6963f7d28e17f72"
    assert hashes.sha1 == "a9993e364706816aba3e25717850c26c9cd0d89d"
    assert hashes.sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
