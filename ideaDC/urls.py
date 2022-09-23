from cms.sitemaps import CMSSitemap
from django.conf import settings
from django.conf.urls.i18n import i18n_patterns
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.sitemaps.views import sitemap
from django.urls import include, path
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.conf.urls import handler404
admin.autodiscover()



urlpatterns = [
    path("", include("home.urls")),
    path("user/", include("user.urls")),
    path('accounts/', include('allauth.urls')),  # for social site URL
    path("sitemap.xml", sitemap, {"sitemaps": {"cmspages": CMSSitemap}}),
]

handler404 = "user.views.error_404_view"

urlpatterns += i18n_patterns(path("admin/", admin.site.urls),
                             path("", include("cms.urls")))


# This is only needed when using runserver.
# if settings.DEBUG:
#     # urlpatterns += staticfiles_urlpatterns()
urlpatterns += static(settings.MEDIA_URL,
                      document_root=settings.MEDIA_ROOT)
urlpatterns += static(settings.STATIC_URL,
                      document_root=settings.STATIC_ROOT)
# if settings.PRODUCTION:
#     urlpatterns += static(settings.MEDIA_URL,
#                           document_root=settings.MEDIA_ROOT)
#     urlpatterns += static(settings.STATIC_URL,
#                           document_root=settings.STATIC_ROOT)
