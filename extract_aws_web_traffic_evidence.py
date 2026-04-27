#!/usr/bin/env python3
import argparse
import gzip
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError


KEYWORDS = re.compile(
    r"(ecs|nginx|php|fpm|wordpress|wp|waf|alb|elb|load|access|application|container)",
    re.I,
)


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value)[:180]


def write_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str))


def client(service, region):
    return boto3.client(service, region_name=region)


def paginate(c, method, result_key, **kwargs):
    paginator = c.get_paginator(method)
    items = []
    for page in paginator.paginate(**kwargs):
        items.extend(page.get(result_key, []))
    return items


def try_call(label, func, default=None):
    try:
        print(f"[*] {label}")
        return func()
    except ClientError as e:
        print(f"[!] {label} failed: {e.response.get('Error', {}).get('Message', e)}")
        return default
    except Exception as e:
        print(f"[!] {label} failed: {e}")
        return default


def export_identity(out, region):
    sts = client("sts", region)
    write_json(out / "inventory" / "aws_identity.json", sts.get_caller_identity())


def export_elb(out, region):
    elbv2 = client("elbv2", region)
    lbs = try_call(
        "Discovering load balancers",
        lambda: paginate(elbv2, "describe_load_balancers", "LoadBalancers"),
        [],
    )
    write_json(out / "alb" / "load_balancers.json", lbs)

    log_locations = []

    for lb in lbs:
        arn = lb["LoadBalancerArn"]
        name = safe_name(lb["LoadBalancerName"])
        attrs = try_call(
            f"Reading attributes for {lb['LoadBalancerName']}",
            lambda arn=arn: elbv2.describe_load_balancer_attributes(
                LoadBalancerArn=arn
            ).get("Attributes", []),
            [],
        )
        write_json(out / "alb" / f"attributes_{name}.json", attrs)

        attr_map = {a["Key"]: a.get("Value", "") for a in attrs}
        if attr_map.get("access_logs.s3.enabled") == "true":
            log_locations.append(
                {
                    "load_balancer": lb,
                    "bucket": attr_map.get("access_logs.s3.bucket"),
                    "prefix": attr_map.get("access_logs.s3.prefix", ""),
                }
            )

    write_json(out / "alb" / "alb_log_locations.json", log_locations)
    return log_locations


def download_s3_prefix(out, region, bucket, prefix, label):
    s3 = boto3.resource("s3", region_name=region)
    dest = out / "s3" / safe_name(label)
    dest.mkdir(parents=True, exist_ok=True)

    print(f"[*] Downloading s3://{bucket}/{prefix} -> {dest}")

    count = 0
    for obj in s3.Bucket(bucket).objects.filter(Prefix=prefix or ""):
        if obj.key.endswith("/"):
            continue
        local = dest / obj.key.replace("/", "__")
        local.parent.mkdir(parents=True, exist_ok=True)
        try:
            s3.Bucket(bucket).download_file(obj.key, str(local))
            count += 1
        except Exception as e:
            print(f"[!] Failed downloading {obj.key}: {e}")

    return count


def export_waf(out, region):
    all_configs = []

    for scope, waf_region in [("REGIONAL", region), ("CLOUDFRONT", "us-east-1")]:
        waf = client("wafv2", waf_region)

        acls = try_call(
            f"Discovering WAFv2 Web ACLs {scope}",
            lambda: paginate(waf, "list_web_ac_ls", "WebACLs", Scope=scope),
            [],
        )

        # boto3 method name is awkward to call through paginator above on some versions.
        if not acls:
            try:
                pages = waf.get_paginator("list_web_acls").paginate(Scope=scope)
                acls = [x for p in pages for x in p.get("WebACLs", [])]
            except Exception as e:
                print(f"[!] WAF list failed for {scope}: {e}")
                acls = []

        write_json(out / "waf" / f"web_acls_{scope}.json", acls)

        for acl in acls:
            name = acl["Name"]
            acl_id = acl["Id"]
            arn = acl["ARN"]
            safe = safe_name(f"{scope}_{name}_{acl_id}")

            detail = try_call(
                f"Reading WAF ACL {name}",
                lambda: waf.get_web_acl(Name=name, Scope=scope, Id=acl_id),
                {},
            )
            write_json(out / "waf" / f"web_acl_{safe}.json", detail)

            logging = try_call(
                f"Reading WAF logging config {name}",
                lambda: waf.get_logging_configuration(ResourceArn=arn),
                {},
            )
            write_json(out / "waf" / f"logging_{safe}.json", logging)

            if logging and "LoggingConfiguration" in logging:
                all_configs.append(
                    {
                        "scope": scope,
                        "region": waf_region,
                        "name": name,
                        "arn": arn,
                        "logging": logging["LoggingConfiguration"],
                    }
                )

    write_json(out / "waf" / "waf_logging_destinations.json", all_configs)
    return all_configs


def export_cloudwatch(out, region, days_back):
    logs = client("logs", region)
    groups = try_call(
        "Discovering CloudWatch log groups",
        lambda: paginate(logs, "describe_log_groups", "logGroups"),
        [],
    )
    write_json(out / "cloudwatch" / "log_groups.json", groups)

    relevant = [g for g in groups if KEYWORDS.search(g.get("logGroupName", ""))]
    write_json(out / "cloudwatch" / "relevant_log_groups.json", relevant)

    start_ms = int((datetime.now(timezone.utc) - timedelta(days=days_back)).timestamp() * 1000)

    for group in relevant:
        name = group["logGroupName"]
        print(f"[*] Exporting CloudWatch events: {name}")

        events = []
        try:
            paginator = logs.get_paginator("filter_log_events")
            for page in paginator.paginate(
                logGroupName=name,
                startTime=start_ms,
                interleaved=True,
            ):
                events.extend(page.get("events", []))
        except Exception as e:
            print(f"[!] Could not export {name}: {e}")
            continue

        safe = safe_name(name)
        write_json(out / "cloudwatch" / f"{safe}.json", events)

        with open(out / "cloudwatch" / f"{safe}.jsonl", "w") as f:
            for ev in events:
                f.write(json.dumps(ev, default=str) + "\n")


def export_ecs(out, region):
    ecs = client("ecs", region)

    clusters = try_call(
        "Discovering ECS clusters",
        lambda: paginate(ecs, "list_clusters", "clusterArns"),
        [],
    )
    write_json(out / "ecs" / "clusters.json", clusters)

    for cluster in clusters:
        safe_cluster = safe_name(cluster)

        services = try_call(
            f"Listing ECS services {cluster}",
            lambda: paginate(ecs, "list_services", "serviceArns", cluster=cluster),
            [],
        )
        write_json(out / "ecs" / f"services_{safe_cluster}.json", services)

        for i in range(0, len(services), 10):
            batch = services[i : i + 10]
            details = try_call(
                f"Describing ECS services batch {i}",
                lambda batch=batch: ecs.describe_services(
                    cluster=cluster,
                    services=batch,
                ).get("services", []),
                [],
            )
            write_json(out / "ecs" / f"service_details_{safe_cluster}_{i}.json", details)

            for svc in details:
                td = svc.get("taskDefinition")
                if not td:
                    continue
                td_detail = try_call(
                    f"Describing task definition {td}",
                    lambda td=td: ecs.describe_task_definition(taskDefinition=td),
                    {},
                )
                write_json(out / "ecs" / f"task_definition_{safe_name(td)}.json", td_detail)


def export_cloudtrail(out, region, days_back):
    ct = client("cloudtrail", region)
    start = datetime.now(timezone.utc) - timedelta(days=days_back)
    end = datetime.now(timezone.utc)

    sources = [
        "elasticloadbalancing.amazonaws.com",
        "wafv2.amazonaws.com",
        "ecs.amazonaws.com",
        "logs.amazonaws.com",
        "s3.amazonaws.com",
        "cloudfront.amazonaws.com",
    ]

    for source in sources:
        events = try_call(
            f"CloudTrail lookup {source}",
            lambda source=source: paginate(
                ct,
                "lookup_events",
                "Events",
                StartTime=start,
                EndTime=end,
                LookupAttributes=[
                    {"AttributeKey": "EventSource", "AttributeValue": source}
                ],
            ),
            [],
        )
        write_json(out / "cloudtrail" / f"{safe_name(source)}.json", events)


def export_s3_inventory(out, region):
    s3c = client("s3", region)

    buckets = try_call("Listing S3 buckets", lambda: s3c.list_buckets().get("Buckets", []), [])
    write_json(out / "s3" / "buckets.json", buckets)

    interesting = []

    for bucket in buckets:
        name = bucket["Name"]
        if re.search(r"(log|logs|alb|elb|waf|cloudtrail|access|nginx|wordpress|wp)", name, re.I):
            interesting.append(name)

        for api_name, filename in [
            ("get_bucket_logging", "logging"),
            ("get_bucket_location", "location"),
            ("get_bucket_versioning", "versioning"),
        ]:
            data = try_call(
                f"S3 {api_name} {name}",
                lambda api_name=api_name, name=name: getattr(s3c, api_name)(Bucket=name),
                {},
            )
            write_json(out / "s3" / "bucket_metadata" / f"{safe_name(name)}_{filename}.json", data)

    write_json(out / "s3" / "interesting_buckets.json", interesting)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "eu-west-2"))
    parser.add_argument("--days-back", type=int, default=3650)
    parser.add_argument("--out", default=None)
    parser.add_argument("--download-alb-logs", action="store_true", default=True)
    args = parser.parse_args()

    out = Path(args.out or f"aws_web_traffic_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    out.mkdir(parents=True, exist_ok=True)

    export_identity(out, args.region)
    alb_locations = export_elb(out, args.region)
    waf_configs = export_waf(out, args.region)
    export_cloudwatch(out, args.region, args.days_back)
    export_ecs(out, args.region)
    export_cloudtrail(out, args.region, args.days_back)
    export_s3_inventory(out, args.region)

    for loc in alb_locations:
        bucket = loc.get("bucket")
        prefix = loc.get("prefix") or ""
        if bucket:
            download_s3_prefix(out, args.region, bucket, prefix, f"alb_{bucket}_{prefix}")

    write_json(
        out / "SUMMARY.json",
        {
            "output_dir": str(out),
            "region": args.region,
            "days_back": args.days_back,
            "alb_log_locations_found": alb_locations,
            "waf_logging_configs_found": waf_configs,
            "notes": [
                "CloudWatch export is limited to log groups matching web-related names.",
                "If ALB access logging was disabled historically, old traffic logs may not exist.",
                "WAF full logs only exist if WAF logging was previously configured.",
                "CloudTrail lookup-events normally has limited retention unless trail logs were delivered to S3/CloudWatch.",
            ],
        },
    )

    print()
    print("[+] Complete")
    print(f"[+] Output directory: {out}")
    print(f"[+] Review: {out / 'SUMMARY.json'}")


if __name__ == "__main__":
    main()