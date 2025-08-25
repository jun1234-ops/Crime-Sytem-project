from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import Criminal, CrimeCatalog, Complaint, Suspect

# ==================== Criminal Form ==================== #
class CriminalForm(forms.ModelForm):
    crime_type = forms.CharField(
        required=True,
        widget=forms.TextInput(attrs={'class': 'form-control', 'id': 'id_crime_type', 'placeholder': 'Enter or select crime type'})
    )

    class Meta:
        model = Criminal
        fields = '__all__'
        widgets = {
            'date_of_birth': forms.DateInput(attrs={'type': 'date'}),
            'date_of_conviction': forms.DateInput(attrs={'type': 'date'}),
            'gender': forms.Select(attrs={'class': 'form-control'}),
            'sentence_details': forms.Select(attrs={'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        super(CriminalForm, self).__init__(*args, **kwargs)
        self.fields['crime_type'].label = "Crime Type (Type or Select)"

# ==================== Signup Form ==================== #
class CustomSignupForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2')

# ==================== Crime Catalog Form ==================== #
class CrimeCatalogForm(forms.ModelForm):
    class Meta:
        model = CrimeCatalog
        fields = ['crime_name', 'description']
        widgets = {
            'crime_name': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control'}),
        }

# ==================== Complaint Form ==================== #
from .models import Complaint

RELATIONSHIP_CHOICES = [
    ('victim', 'Victim'),
    ('witness', 'Witness'),
    ('third_party', 'Third Party Reporter'),
]

COMPLAINT_STATUS_CHOICES = [
    ('new', 'New'),
    ('under_review', 'Under Review'),
    ('in_progress', 'In Progress'),
    ('resolved', 'Resolved'),
    ('closed', 'Closed'),
]

CRIME_TYPE_CHOICES = [
    ('theft', 'Theft'),
    ('assault', 'Assault'),
    ('fraud', 'Fraud'),
    ('kidnapping', 'Kidnapping'),
    ('other', 'Other'),
]

class ComplaintForm(forms.ModelForm):
    full_name = forms.CharField(
        label='Complainant Full Name', 
        max_length=100,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter Full Name'})
    )
    phone_number = forms.CharField(
        label='Phone Number', 
        max_length=15,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter Phone Number'})
    )
    email = forms.EmailField(
        label='Email',
        widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Enter Email'})
    )
    date_time_of_incident = forms.DateTimeField(
        label='Date and Time of Incident',
        widget=forms.DateTimeInput(attrs={'type': 'datetime-local', 'class': 'form-control'})
    )

    crime_type = forms.CharField(
        label='Crime Type',
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'list': 'crime-catalog-list',  # HTML5 datalist for suggestions
            'placeholder': 'Type or select a crime type'
        })
    )
     
    crime_description = forms.CharField(
        label='Crime Description',
        widget=forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'Describe the crime here...'})
    )
    relationship = forms.ChoiceField(
        label='Relationship to Incident',
        choices=RELATIONSHIP_CHOICES,
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    location = forms.CharField(
        label='Location of Crime',
        max_length=200,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter Location of Crime',
            'autocomplete': 'off' 
        })
    )
    
    suspect_description = forms.CharField(
        label='Suspect Description (if known)',
        widget=forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'Describe the suspect if known'}),
        required=False
    )
    evidence = forms.FileField(
        label='Evidence Provided (Photo, Video, Document)',
        required=False,
        widget=forms.ClearableFileInput(attrs={'class': 'form-control', 'accept': 'image/*,video/*,.pdf,.doc,.docx'})
    )
    complaint_status = forms.ChoiceField(
        label='Complaint Status',
        choices=COMPLAINT_STATUS_CHOICES,
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    class Meta:
        model = Complaint
        exclude = ['user','complaint_status', 'is_anonymous', 'crime_type']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # populate crime_type choices from existing CrimeCatalog
        existing_crimes = CrimeCatalog.objects.values_list('crime_name', flat=True)
        choices = [(crime, crime) for crime in existing_crimes]
        self.fields['crime_type'].choices = choices

# ==================== Suspect Registration Form ==================== #
from django import forms
from .models import Suspect, CrimeCatalog

class SuspectRegistrationForm(forms.ModelForm):
    crime_type = forms.CharField(
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        help_text="Enter a known or new crime type."
    )

    class Meta:
        model = Suspect
        fields = '__all__'
        widgets = {
            'date_of_birth': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'gender': forms.Select(attrs={'class': 'form-control'}),
            'address': forms.Textarea(attrs={'class': 'form-control'}),
            'known_associates': forms.Textarea(attrs={'class': 'form-control'}),
            'previous_criminal_records': forms.Textarea(attrs={'class': 'form-control'}),
            'suspect_description': forms.Textarea(attrs={'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        super(SuspectRegistrationForm, self).__init__(*args, **kwargs)
        self.fields['crime_type'].label = "Crime Type"

    def clean_crime_type(self):
        crime_name = self.cleaned_data['crime_type'].strip()

        # Search case-insensitively
        crime, created = CrimeCatalog.objects.get_or_create(
            crime_name__iexact=crime_name,
            defaults={
                'crime_name': crime_name,
                'description': 'Auto-added from suspect form.',
                'category': 'other',
                'severity': 'low',
            }
        )
        return crime

# ==================== Anonymous compliant Form ==================== #
from .models import AnonymousComplaint

class AnonymousComplaintForm(forms.ModelForm):
    crime_type = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))                            
    class Meta:
        model = AnonymousComplaint
        exclude = ['user', 'complaint_status', 'is_anonymous']
        widgets = {
            'incident_datetime': forms.DateTimeInput(attrs={'type': 'datetime-local', 'class': 'form-control'}),
            'location': forms.TextInput(attrs={'class': 'form-control', 'autocomplete': 'off'}),
            'crime_description': forms.Textarea(attrs={'rows': 3, 'class': 'form-control'}),
            'suspect_description': forms.Textarea(attrs={'rows': 3, 'class': 'form-control'}),
            'other_notes': forms.Textarea(attrs={'rows': 3, 'class': 'form-control'}),
            'preferred_response_channel': forms.Select(attrs={'class': 'form-control'}),
            'witnessed_directly': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'is_emergency': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            if not isinstance(field.widget, forms.CheckboxInput):
                field.widget.attrs.setdefault('class', 'form-control')
