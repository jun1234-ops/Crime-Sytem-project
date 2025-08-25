from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class Suspect(models.Model):
    GENDER_CHOICES = [
        ('Male', 'Male'),
        ('Female', 'Female'),
        ('Other', 'Other'),
    ]

    full_name = models.CharField(max_length=100)
    nickname = models.CharField(max_length=50, blank=True, null=True)
    date_of_birth = models.DateField()
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES)
    address = models.TextField()
    phone_number = models.CharField(max_length=15)
    email = models.EmailField()
    national_id = models.CharField(max_length=50)
    crime_type = models.ForeignKey("CrimeCatalog", on_delete=models.SET_NULL, null=True)
    height = models.DecimalField(max_digits=5, decimal_places=2)
    weight = models.DecimalField(max_digits=5, decimal_places=2)
    skin_color = models.CharField(max_length=50)
    hair_color = models.CharField(max_length=50)
    picture = models.ImageField(upload_to='suspect_pictures/', blank=True, null=True)
    known_associates = models.TextField(blank=True, null=True)
    previous_criminal_records = models.TextField(blank=True, null=True)
    current_status = models.CharField(max_length=50, choices=[
        ('Arrested', 'Arrested'),
        ('Under Investigation', 'Under Investigation'),
        ('Released', 'Released')
    ])

    def __str__(self):
        return self.full_name

class Criminal(models.Model):
    GENDER_CHOICES = [
        ('Male', 'Male'),
        ('Female', 'Female'),
    ]

    SENTENCE_CHOICES = [
        ('Jail Term', 'Jail Term'),
        ('Fine', 'Fine'),
        ('Probation Details', 'Probation Details'),
    ]

    full_name = models.CharField(max_length=100)
    criminal_id_number = models.CharField(max_length=50, unique=True)
    date_of_birth = models.DateField()
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES)
    address = models.TextField()
    phone_number = models.CharField(max_length=15)
    email = models.EmailField()
    photograph = models.ImageField(upload_to='criminal_photos/', blank=True, null=True)
    date_of_conviction = models.DateTimeField(default=timezone.now, null=False, blank=False)
    crime_type = models.ForeignKey('CrimeCatalog', on_delete=models.SET_NULL, null=True)
    sentence_details = models.CharField(max_length=50, choices=SENTENCE_CHOICES)
    fingerprint = models.ImageField(upload_to='fingerprints/', blank=True, null=True)
    known_associates = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.full_name


from django.db import models
from django.contrib.auth.models import User

# Choices used in the form and model
RELATIONSHIP_CHOICES = [
    ('victim', 'Victim'),
    ('witness', 'Witness'),
    ('relative', 'Relative'),
    ('neighbor', 'Neighbor'),
    ('anonymous', 'Anonymous'),
    ('other', 'Other'),
]

COMPLAINT_STATUS_CHOICES = [
    ('new', 'New'),
    ('under_review', 'Under Review'),
    ('in_progress', 'In Progress'),
    ('resolved', 'Resolved'),
    ('closed', 'Closed'),
]

class CrimeCatalog(models.Model):
    crime_name = models.CharField(max_length=100, unique=True)
    description = models.TextField()
    category = models.CharField(max_length=50, choices=[
        ('violent', 'Violent Crime'),
        ('property', 'Property Crime'),
        ('cyber', 'Cybercrime'),
        ('fraud', 'Fraud'),
        ('other', 'Other'),
    ], default='other')
    severity = models.CharField(max_length=10, choices=[
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    ], default='low')
    penalty = models.TextField(blank=True, null=True)
    law_reference = models.CharField(max_length=100, blank=True, null=True)
    reportable = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)

    def save(self, *args, **kwargs):
        self.crime_name = self.crime_name.strip().title()  # Normalize case/title
        super().save(*args, **kwargs)

    def __str__(self):
        return self.crime_name


class Complaint(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    full_name = models.CharField(max_length=100)
    phone_number = models.CharField(max_length=15)
    email = models.EmailField()
    

    date_time_of_incident = models.DateTimeField(default=timezone.now, null=False, blank=False)
    crime_type = models.ForeignKey(CrimeCatalog, on_delete=models.SET_NULL, null=True)
    crime_description = models.TextField()

    relationship = models.CharField(
        max_length=50,
        choices=RELATIONSHIP_CHOICES
    )

    location = models.CharField(max_length=200)
    suspect_description = models.TextField(blank=True, null=True)

    evidence = models.FileField(
        upload_to='complaint_evidence/', blank=True, null=True
    )

    complaint_status = models.CharField(
        max_length=50,
        choices=COMPLAINT_STATUS_CHOICES,
        default='new'
    )
    is_anonymous = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.full_name} - {self.crime_type}"
    

SEVERITY_CHOICES = [
    ('Low', 'Low'),
    ('Moderate', 'Moderate'),
    ('High', 'High'),
    ('Critical', 'Critical'),
]

RESPONSE_CHANNEL_CHOICES = [
    ('Phone Call', 'Phone Call'),
    ('Email', 'Email'),
    ('SMS', 'SMS'),
    ('None', 'None'),
]

RELATIONSHIP_CHOICES = [
    ('Victim', 'Victim'),
    ('Witness', 'Witness'),
    ('Concerned Citizen', 'Concerned Citizen'),
    ('Other', 'Other'),
]

class AnonymousComplaint(models.Model):
    is_anonymous = models.BooleanField(default=True)

    incident_datetime = models.DateTimeField(default=timezone.now, null=False, blank=False)
    crime_type = models.CharField(max_length=100)
    crime_description = models.TextField()
    suspect_description = models.TextField()
    location_of_crime = models.CharField(max_length=255)
    evidence_provided = models.FileField(upload_to='evidence/', null=True, blank=True)

    crime_severity_estimate = models.CharField(
        max_length=10,
        choices=SEVERITY_CHOICES
    )
    
    witnessed_directly = models.BooleanField(default=False)
    
    reporter_relationship = models.CharField(
        max_length=50,
        choices=RELATIONSHIP_CHOICES
    )

    is_emergency = models.BooleanField(default=False)
    
    preferred_response_channel = models.CharField(
        max_length=100,
        choices=RESPONSE_CHANNEL_CHOICES,
        default='None'
    )
    
    other_notes = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"Anonymous Complaint on {self.incident_datetime or 'Unknown Date'}"


from django.contrib.auth.models import User

class ActivityLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    action = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.user.username} - {self.action} at {self.timestamp}'

