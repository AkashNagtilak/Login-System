from django.db import models
from django.db.models import ForeignKey


class Type(models.Model):
    parent = ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True)

def cname():
    return None