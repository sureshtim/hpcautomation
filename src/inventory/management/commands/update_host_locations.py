import csv
import os
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from inventory.models import Host, HPCCluster, HostType, HostStatus


class Command(BaseCommand):
    help = "Import/update Host records from CSV asset list. Creates missing hosts. Maps fields as specified."

    def add_arguments(self, parser):
        parser.add_argument(
            "--csv",
            required=True,
            help="Path to CSV file (Most Recent Asset List -data-*.csv)",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Simulate without saving to DB",
        )
        parser.add_argument(
            "--default-domain",
            default=".edc.nam.gm.com",
            help="Domain used for FQDN and idrac_host",
        )
        parser.add_argument(
            "--default-cluster",
            default="Not-In-Cluster",  # ← this is now the fallback value
            help="Fallback cluster name for new hosts when no prefix matches",
        )

    def handle(self, *args, **opts):
        csv_path = opts["csv"]
        dry = opts["dry_run"]
        default_domain = opts["default_domain"]
        default_cluster_name = opts["default_cluster"]

        if not os.path.exists(csv_path):
            self.stdout.write(self.style.ERROR(f"CSV not found: {csv_path}"))
            return

        self.stdout.write(f"Reading CSV: {csv_path}")
        if dry:
            self.stdout.write(self.style.WARNING("DRY RUN - no database writes"))

        updates = []
        creates = []
        matched = 0
        created = 0
        skipped = 0

        # Cache clusters
        cluster_cache = {}

        def get_or_create_cluster(name):
            if name not in cluster_cache:
                cluster, _ = HPCCluster.objects.get_or_create(
                    name=name,
                    defaults={"enabled": True}
                )
                cluster_cache[name] = cluster
            return cluster_cache[name]

        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)

            for row_num, row in enumerate(reader, 1):
                short_host = (row.get("configuration item") or "").strip()
                if not short_host:
                    skipped += 1
                    continue

                short_host_lower = short_host.lower()

                # ── Map fields from CSV ───────────────────────────────────────────────
                csv_location    = (row.get("location") or "").strip()
                csv_rack        = (row.get("rack") or "").strip()
                csv_quad        = (row.get("roomcube") or "").strip()
                csv_shelf       = (row.get("shelf") or "").strip()
                csv_serial      = (row.get("serial number") or "").strip()
                csv_asset_tag   = (row.get("asset tag") or "").strip()
                csv_model       = (row.get("model") or "").strip()
                csv_hpctype     = (row.get("hpctype") or "").strip().lower()

                # ── Derived fields ───────────────────────────────────────────────────
                fqdn = f"{short_host}{default_domain}"
                idrac_fqdn = fqdn.replace("ph", "rm")  # dcwipphpc1793 → dcwiprmpc1793...

                # Guess cluster
                cluster_name = "Not-In-Cluster"  # ← default value as requested
                # if short_host_lower.startswith("dcwip"):
                #     cluster_name = "SUBMIT_GMNA"
                # elif short_host_lower.startswith("dcmip"):
                #     cluster_name = "MILFORD_HPC"
                # Add more prefix rules here if needed

                # Host type inference
                host_type = HostType.COMPUTE
                if csv_hpctype and "infra" in csv_hpctype:
                    host_type = "infra"
                elif csv_hpctype and "viz" in csv_hpctype:
                    host_type = "viz"
                elif "viz" in short_host_lower:
                    host_type = "viz"
                elif any(x in short_host_lower for x in ["xp", "infra"]):
                    host_type = "infra"

                # Status: "-" if not a valid choice
                status_value = "-"
                valid_statuses = [choice[0] for choice in HostStatus.choices]
                if csv_hpctype and csv_hpctype.upper() in valid_statuses:
                    status_value = csv_hpctype.upper()

                # Find existing host
                existing = Host.objects.filter(hostname__icontains=short_host_lower)

                if existing.exists():
                    for host in existing:
                        host.hostname      = fqdn                     # ensure consistent
                        host.host_type     = host_type
                        host.status        = status_value
                        host.idrac_host    = idrac_fqdn
                        host.hw_model      = csv_model
                        host.bios_version  = "-"                      # no source
                        host.location      = csv_location
                        host.rack          = csv_rack
                        host.quad          = csv_quad
                        host.shelf         = csv_shelf
                        host.serialnumber  = csv_serial
                        host.asset_tag     = csv_asset_tag
                        updates.append(host)
                    matched += len(existing)
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"Row {row_num:5d}: Updated {len(existing)} host(s) → {short_host}"
                        )
                    )
                else:
                    # Create new host
                    cluster = get_or_create_cluster(cluster_name)

                    new_host = Host(
                        cluster=cluster,
                        hostname=fqdn,
                        host_type=host_type,
                        status=status_value,
                        enabled=True,
                        idrac_host=idrac_fqdn,
                        hw_model=csv_model,
                        bios_version="-",
                        location=csv_location,
                        rack=csv_rack,
                        quad=csv_quad,
                        shelf=csv_shelf,
                        serialnumber=csv_serial,
                        asset_tag=csv_asset_tag,
                        last_seen=timezone.now(),
                    )
                    creates.append(new_host)
                    created += 1
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"Row {row_num:5d}: Created new host → {fqdn} (cluster: {cluster_name})"
                        )
                    )

        # ── Summary ────────────────────────────────────────────────────────────────
        self.stdout.write("\n" + "═" * 70)
        self.stdout.write("Import Summary:")
        self.stdout.write(f"  Updated existing hosts : {matched}")
        self.stdout.write(f"  Created new hosts      : {created}")
        self.stdout.write(f"  Skipped (empty rows)   : {skipped}")
        self.stdout.write(f"  Total processed        : {matched + created + skipped}")
        self.stdout.write("═" * 70 + "\n")

        if dry:
            self.stdout.write(self.style.SUCCESS("Dry run complete — no changes saved."))
            return

        if updates or creates:
            with transaction.atomic():
                if updates:
                    Host.objects.bulk_update(
                        updates,
                        [
                            "hostname", "host_type", "status", "idrac_host",
                            "hw_model", "bios_version", "location", "rack",
                            "quad", "shelf", "serialnumber", "asset_tag"
                        ],
                        batch_size=1000
                    )
                    self.stdout.write(self.style.SUCCESS(f"Updated {len(updates)} existing records"))

                if creates:
                    Host.objects.bulk_create(creates, batch_size=1000, ignore_conflicts=True)
                    self.stdout.write(self.style.SUCCESS(f"Created {len(creates)} new hosts"))

            self.stdout.write(self.style.SUCCESS("Database sync complete."))
        else:
            self.stdout.write(self.style.WARNING("No changes were needed."))