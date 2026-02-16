from django.db import models
from django.utils import timezone

class HostType(models.TextChoices):
    COMPUTE = "compute", "compute"
    INFRA = "infra", "infra"
    VIZ = "viz", "viz"


class HostStatus(models.TextChoices):
    AVAILABLE = "available", "available"
    UNAVAILABLE = "unavailable", "unavailable"
    CLOSED = "closed", "closed"


class HPCCluster(models.Model):
    """
    Example: NAHPC_MPG
    """
    name = models.CharField(max_length=128, unique=True)
    enabled = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.name

    # Helpful functions
    def hosts(self):
        return self.hpc_hosts.all()

    def available_hosts(self):
        return self.hpc_hosts.filter(status=HostStatus.AVAILABLE, enabled=True)

    def unavailable_hosts(self):
        return self.hpc_hosts.filter(status=HostStatus.UNAVAILABLE, enabled=True)

    def hosts_by_type(self, host_type: str):
        return self.hpc_hosts.filter(host_type=host_type, enabled=True)


class Host(models.Model):
    """
    Example hostnames: host1, host2, infra1, infra2, vis1, vis2
    """
    cluster = models.ForeignKey(HPCCluster, related_name="hpc_hosts", on_delete=models.CASCADE)

    hostname = models.CharField(max_length=255)
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

    last_seen = models.DateTimeField(null=True, blank=True)
    last_status_change = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

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


class StorageCluster(models.Model):
    """
    Example: gmhpc4
    """
    name = models.CharField(max_length=128, unique=True)
    enabled = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.name

    # Helpful functions
    def ces_nodes(self):
        return self.ces.all()

    def active_ces(self):
        return self.ces.filter(status=CESStatus.ACTIVE, enabled=True)

    def sfa_primary(self):
        return self.sfa.filter(role=SFARole.PRIMARY, enabled=True).first()

    def sfa_secondary(self):
        return self.sfa.filter(role=SFARole.SECONDARY, enabled=True).first()

    def has_sfa_pair(self) -> bool:
        return bool(self.sfa_primary() and self.sfa_secondary())


class CESStatus(models.TextChoices):
    ACTIVE = "active", "active"
    NOTACTIVE = "notactive", "notactive"


class CESNode(models.Model):
    """
    Example: ces1, ces2, ces3
    """
    storage = models.ForeignKey(StorageCluster, related_name="ces", on_delete=models.CASCADE)

    hostname = models.CharField(max_length=255)
    status = models.CharField(max_length=16, choices=CESStatus.choices, default=CESStatus.ACTIVE)
    enabled = models.BooleanField(default=True)
    host_type = models.CharField(max_length=16, choices=HostType.choices, default=HostType.COMPUTE)
    idrac_host = models.CharField(max_length=255, blank=True, null=True)
    hw_model = models.CharField(max_length=255, blank=True, null=True)
    bios_version = models.CharField(max_length=255, null=True, blank=True)
    location = models.CharField(max_length=255, blank=True, null=True)
    rack = models.CharField(max_length=255, blank=True, null=True)
    quad = models.CharField(max_length=255, blank=True, null=True)
    shelf = models.CharField(max_length=255, blank=True, null=True)
    serialnumber = models.CharField(max_length=255, blank=True, null=True)
    asset_tag = models.CharField(max_length=255, blank=True, null=True)

    last_seen = models.DateTimeField(null=True, blank=True)
    last_status_change = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


    class Meta:
        unique_together = [("storage", "hostname")]
        indexes = [
            models.Index(fields=["storage", "status"]),
            models.Index(fields=["hostname"]),
        ]

    def __str__(self) -> str:
        return f"{self.storage.name}:CES:{self.hostname}"

    def set_status(self, new_status: str):
        if new_status != self.status:
            self.status = new_status
            self.last_status_change = timezone.now()
        self.last_seen = timezone.now()
        self.save(update_fields=["status", "last_status_change", "last_seen", "updated_at"])


class SFARole(models.TextChoices):
    PRIMARY = "primary", "primary"
    SECONDARY = "secondary", "secondary"


class SFANode(models.Model):
    """
    Example: sfa1, sfa2 (role=primary/secondary)
    """
    storage = models.ForeignKey(StorageCluster, related_name="sfa", on_delete=models.CASCADE)

    hostname = models.CharField(max_length=255)
    role = models.CharField(max_length=16, choices=SFARole.choices)
    enabled = models.BooleanField(default=True)

    last_seen = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        # ensures exactly one PRIMARY and one SECONDARY per storage cluster
        unique_together = [("storage", "role"), ("storage", "hostname")]
        indexes = [
            models.Index(fields=["storage", "role"]),
            models.Index(fields=["hostname"]),
        ]

    def __str__(self) -> str:
        return f"{self.storage.name}:SFA:{self.role}:{self.hostname}"

    def mark_seen(self):
        self.last_seen = timezone.now()
        self.save(update_fields=["last_seen", "updated_at"])
