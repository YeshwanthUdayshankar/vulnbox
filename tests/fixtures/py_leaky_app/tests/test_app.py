from app import dispatch_action, read_data_file


def test_dispatch_and_read():
    assert int(dispatch_action("store_item", "unit_k")) >= 1
    assert "sample-data" in read_data_file()
