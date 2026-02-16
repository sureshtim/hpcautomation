from django.shortcuts import render
from django.db.models import Q
from .models import Host, HPCCluster


def cluster_hosts_table(request):
    """
    Renders a table of all hosts with their cluster name and host details.
    Optional filter:
      /inventory/cluster-hosts/?cluster=NAHPC_MPG
      /inventory/cluster-hosts/?q=viz
    """
    cluster_name = (request.GET.get("cluster") or "").strip()
    q = (request.GET.get("q") or "").strip()

    hosts = (
        Host.objects
        .select_related("cluster")
        .all()
        .order_by("cluster__name", "hostname")
    )

    if cluster_name:
        hosts = hosts.filter(cluster__name=cluster_name)

    if q:
        hosts = hosts.filter(
            Q(hostname__icontains=q) |
            Q(cluster__name__icontains=q) |
            Q(host_type__icontains=q) |
            Q(status__iexact=q) |           # exact for choices
            Q(idrac_host__icontains=q) |
            Q(hw_model__icontains=q) |
            Q(bios_version__icontains=q) |
            Q(location__icontains=q) |
            Q(rack__icontains=q) |
            Q(quad__icontains=q) |
            Q(shelf__icontains=q) |
            Q(serialnumber__icontains=q) |
            Q(asset_tag__icontains=q)
        )

    clusters = HPCCluster.objects.order_by("name").values_list("name", flat=True)

    context = {
        "hosts": hosts,
        "clusters": clusters,
        "selected_cluster": cluster_name,
        "q": q,
    }
    print(context)
    return render(request, "inventory/cluster_hosts_table.html", context)
