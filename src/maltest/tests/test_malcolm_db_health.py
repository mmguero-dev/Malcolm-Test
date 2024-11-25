def test_malcolm_db_health(
    malcolm_url,
    database_objs,
):
    dbObjs = database_objs
    healthDict = dict(
        dbObjs.DatabaseClass(
            hosts=[
                f"{malcolm_url}/mapi/opensearch",
            ],
            **dbObjs.DatabaseInitArgs,
        ).cluster.health()
    )
    assert healthDict.get("status", "unknown") in ["green", "yellow"]
