from django.db import models
from django.utils import timezone

class HostType(models.TextChoices):
    COMPUTE = "compute", "compute"
    INFRA = "infra", "infra"
    VIZ = "viz", "viz"
    CES = "ces", "ces"
    STORAGEINFRA = "storage-infra", "storage-infra"


class HostStatus(models.TextChoices):
    AVAILABLE = "available", "available"
    UNAVAILABLE = "unavailable", "unavailable"
    CLOSED = "closed", "closed"

class ClusterType(models.TextChoices):
    HPC = "hpc", "hpc"
    STORAGE = "storage", "storage"
    NONE = "none", "none"

class SFARole(models.TextChoices):
    PRIMARY = "primary", "primary"
    SECONDARY = "secondary", "secondary"

class HPCCluster(models.Model):
    name = models.CharField(max_length=128, unique=True)
    enabled = models.BooleanField(default=True)
    cluster_type = models.CharField(max_length=16, choices=HostType.choices, default=ClusterType.HPC)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.name

class HostQuerySet(models.QuerySet):
    def available(self):
        return self.filter(status=HostStatus.AVAILABLE, enabled=True)

    def unavailable(self):
        return self.filter(status=HostStatus.UNAVAILABLE, enabled=True)

    def by_type(self, host_type: str):
        # host_type would be "compute", "infra", etc.
        return self.filter(host_type=host_type, enabled=True)

class Host(models.Model):
    """
    Example hostnames: host1, host2, infra1, infra2, vis1, vis2
    """
    cluster = models.ForeignKey(HPCCluster, related_name="hpc_hosts", on_delete=models.CASCADE)

    hostname = models.CharField(max_length=255, unique=True)  # unique only within cluster (enforced by unique_together)
    host_type = models.CharField(max_length=16, choices=HostType.choices, default=HostType.COMPUTE)
    status = models.CharField(max_length=16, choices=HostStatus.choices, default=HostStatus.AVAILABLE)
    enabled = models.BooleanField(default=True)
    idrac_host = models.CharField(max_length=255)
    hw_model = models.CharField(max_length=255)
    bios_version = models.CharField(max_length=255, blank=True, null=True)
    location = models.CharField(max_length=255, blank=True, null=True)
    rack = models.CharField(max_length=255, blank=True, null=True)
    quad = models.CharField(max_length=255, blank=True, null=True)
    shelf = models.CharField(max_length=255, blank=True, null=True)
    serialnumber = models.CharField(max_length=255, blank=True, null=True)
    asset_tag = models.CharField(max_length=255, blank=True, null=True)
    used_for = models.CharField(max_length=255, blank=True, null=True)
    os_type = models.CharField(max_length=255, blank=True, null=True)
    kernal_version = models.CharField(max_length=255, blank=True, null=True)

    last_seen = models.DateTimeField(null=True, blank=True)
    last_status_change = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    objects = HostQuerySet.as_manager()

    class Meta:
        unique_together = [("cluster", "hostname")]
        indexes = [
            models.Index(fields=["cluster", "host_type"]),
            models.Index(fields=["cluster", "status"]),
            models.Index(fields=["hostname"]),
        ]

    def __str__(self) -> str:
        return f"{self.cluster.name}:{self.hostname}"

    # Helpful functions
    def set_status(self, new_status: str):
        if new_status != self.status:
            self.status = new_status
            self.last_status_change = timezone.now()
        self.last_seen = timezone.now()
        self.save(update_fields=["status", "last_status_change", "last_seen", "updated_at"])
        
    def hosts(self):
        return Host.objects.all()

    def available_hosts(self):
        return self.filter(status=HostStatus.AVAILABLE, enabled=True)

    def unavailable_hosts(self):
        return self.filter(status=HostStatus.UNAVAILABLE, enabled=True)

    def hosts_by_type(self, host_type: str):
        return self.filter(host_type=host_type, enabled=True)
