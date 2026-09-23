import json, subprocess, time, sys

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
BASE = "https://fortnite.en.uptodown.com/android/apps/725251/versions/{}"

def fetch(url):
    r = subprocess.run(["curl","-sL","-A",UA,"-H","X-Requested-With: XMLHttpRequest","-H","Accept: application/json",url],capture_output=True,text=True)
    return r.stdout

all_versions = []
page = 1
while page <= 60:
    body = fetch(BASE.format(page))
    try:
        data = json.loads(body)
    except Exception:
        print("NON-JSON at page", page, body[:200]); break
    if data.get("success") != 1 or not data.get("data"):
        print("END at page", page, "->", str(data)[:200]); break
    items = data["data"]
    for it in items:
        all_versions.append({
            "fileID": it.get("fileID"),
            "version": it.get("version"),
            "date": it.get("lastUpdate"),
            "kind": it.get("kindFile"),
            "id": it.get("versionURL",{}).get("versionID"),
        })
    first, last = items[0], items[-1]
    print(f"page {page}: {len(items)} items  {first.get('version')} ({first.get('lastUpdate')}) -> {last.get('version')} ({last.get('lastUpdate')})")
    if last.get("lastUpdate","").endswith("2017") or any(str(v.get("version","")).startswith(("5.","6.","7.","8.")) for v in all_versions[-25:]):
        # keep going until we hit 2018-early versions; stop when date is 2018 mid or earlier
        pass
    if "2018" in last.get("lastUpdate",""):
        print("Reached 2018 on page", page)
        # continue a few more pages to get the earliest, but we can stop soon
        extra = 3
        for p in range(page+1, page+1+extra):
            body = fetch(BASE.format(p))
            try: data = json.loads(body)
            except Exception: break
            if data.get("success") != 1 or not data.get("data"): break
            for it in data["data"]:
                all_versions.append({"fileID": it.get("fileID"),"version": it.get("version"),"date": it.get("lastUpdate"),"kind": it.get("kindFile"),"id": it.get("versionURL",{}).get("versionID")})
            print(f"page {p} (extra): {len(data['data'])} items, last date {data['data'][-1].get('lastUpdate')}")
        break
    page += 1
    time.sleep(0.4)

json.dump(all_versions, open("fortnite_versions.json","w"), indent=1)
print("TOTAL:", len(all_versions))
