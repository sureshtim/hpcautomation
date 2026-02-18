from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.renderers import JSONRenderer, TemplateHTMLRenderer

from .registry import get_table

class TablePageView(APIView):
    permission_classes = [IsAuthenticated]
    renderer_classes = [TemplateHTMLRenderer]

    def get(self, request, group: str, table_id: str):
        TableCls = get_table(group, table_id)
        if not TableCls:
            return Response({"detail": "Not found"}, status=404, template_name="404.html")

        table = TableCls()
        if not table.can_view(request.user):
            return Response({"detail": "Forbidden"}, status=403, template_name="403.html")

        return Response({"table": table}, template_name="tables/table_page.html")


class TableDataAPIView(APIView):
    permission_classes = [IsAuthenticated]
    renderer_classes = [JSONRenderer]

    def get(self, request, group: str, table_id: str):
        TableCls = get_table(group, table_id)
        if not TableCls:
            return Response({"detail": "Not found"}, status=404)

        table = TableCls()
        if not table.can_view(request.user):
            return Response({"detail": "Forbidden"}, status=403)

        payload = table.fetch(
            user=request.user,
            page=request.GET.get("page", 1),
            size=request.GET.get("size", table.page_size),
            q=request.GET.get("q"),
            sort=request.GET.get("sort"),
            direction=request.GET.get("dir", "asc"),
        )
        return Response(payload)
