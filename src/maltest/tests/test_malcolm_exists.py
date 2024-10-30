def test_malcolm_exists(malcolm_vm_info):
    assert isinstance(malcolm_vm_info, dict) and malcolm_vm_info.get("ip", None)
