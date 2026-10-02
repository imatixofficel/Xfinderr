WEIGHTS={"has_http_test":40,"update_frequency":20,"config_count":15,"avg_ping_quality":15,"success_rate":10}

def score_source(*,has_http_test,update_ok,config_count,avg_ping,success_rate):
    points=0
    points += WEIGHTS["has_http_test"] if has_http_test else 0
    points += WEIGHTS["update_frequency"] if update_ok else 0
    points += min(WEIGHTS["config_count"], max(0, config_count)/100*WEIGHTS["config_count"])
    points += WEIGHTS["avg_ping_quality"] if 0 < avg_ping <= 200 else (8 if avg_ping <= 500 else 0)
    points += min(WEIGHTS["success_rate"], max(0, success_rate)/100*WEIGHTS["success_rate"])
    return round(points,1)
