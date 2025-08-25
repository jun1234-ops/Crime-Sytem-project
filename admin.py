from django.contrib import admin
from .models import AnonymousComplaint, Suspect, CrimeCatalog

admin.site.register(Suspect)
admin.site.register(CrimeCatalog)

@admin.register(AnonymousComplaint)
class AnonymousComplaintAdmin(admin.ModelAdmin):
    list_display = [
        'incident_datetime',
        'crime_type',
        'crime_severity_estimate',
        'witnessed_directly',
        'is_emergency',
        'preferred_response_channel'
    ]
    list_filter = ['incident_datetime', 'crime_type', 'is_emergency']
    search_fields = ['crime_description', 'suspect_description', 'location_of_crime']
