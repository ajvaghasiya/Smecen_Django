from django.urls import path
from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("product.html", views.product, name="product"),
    path("pricing.html", views.pricing, name="pricing"),
    path("support.html", views.support, name="support"),
    path("contact-us.html", views.contact, name="contact"),
    path("video.html", views.video, name="video"),
    path("privacy-policy.html", views.privacy_policy, name="privacy-policy"),
]
