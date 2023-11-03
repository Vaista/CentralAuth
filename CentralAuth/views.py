from django.shortcuts import redirect


def admin_redirect(request):
    """Redirects to admin interface"""
    return redirect("/admin/")
