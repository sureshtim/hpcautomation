from django.urls import path
from . import views

urlpatterns = [
    path("cluster-hosts/", views.cluster_hosts_table, name="cluster_hosts_table"),
]
