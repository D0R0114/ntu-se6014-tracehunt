from tracehunt_mcp import queries as q


def test_date_histogram_uses_requested_field():
    agg = q.build_agg({"kind": "date_histogram", "field": "event.created", "interval": "1h"})
    assert agg["date_histogram"]["field"] == "event.created"


def test_terms_uses_requested_bucket_limit():
    agg = q.build_agg({"kind": "terms", "field": "user.name"}, bucket_limit=17)
    assert agg["terms"]["size"] == 17
