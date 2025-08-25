from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('user-login/', views.user_login_view, name='user_login'),
    path('admin-login/', views.admin_login_view, name='admin_login'),
    path('', views.user_login_view, name='user_login'),
    path('anonymous-complaint/', views.anonymous_complaint_view, name='anonymous_complaint'),
    path('anonymous-thank-you/', views.anonymous_thank_you, name='anonymous_thank_you'),
    path('report/anonymous-complaint/<int:pk>/', views.anonymous_complaint_detail, name='anonymous_complaint_detail'),
    path('home/', views.home, name='home'),
    path('signup/', views.signup, name='signup'),
    path('activate/<uidb64>/<token>/', views.activate, name='activate'),
    path('logout/', views.custom_logout, name='logout'),

    # Menu paths
    path('file/', views.file_menu, name='file_menu'),
    path('file/suspect-registration/', views.suspect_registration, name='suspect_registration'),
    path('file/suspect_search/', views.suspect_search, name='suspect_search'),
    path('file/suspect/<int:suspect_id>/', views.suspect_detail, name='suspect_detail'),
    path('register-criminal/', views.register_criminal, name='register_criminal'),
    path('file/complaint-form/', views.complaint_view, name='complaint_view'),
    path('my_complaints/', views.view_my_complaints, name='view_my_complaints'),
    path('file/crime-types/', views.crime_types_view, name='crime_types'),
    path('crime-catalog/', views.crime_catalog, name='crime_catalog'),
    path('crime-catalog/add/', views.add_crime, name='add_crime'),
    path('crime_catalog/edit/<int:pk>/', views.edit_crime, name='edit_crime'),
    path('crime_catalog/delete/<int:pk>/', views.delete_crime, name='delete_crime'),
    path('manage-users/', views.manage_users, name='manage_users'),
    path('activity_log/', views.activity_log, name='activity_log'),
    path('system_access/', views.system_access, name='system_access'),
    path('report/', views.report_menu, name='report_menu'),
    path('report/all-complaints/', views.all_complaints_view, name='all_complaints'),
    path('complaint/<int:pk>/', views.complaint_user_detail, name='complaint_user_detail'),
    path('view/complaint/<int:pk>/', views.complaint_detail, name='complaint_detail'),
    path('report/export/pdf/', views.export_complaints_pdf, name='export_complaints_pdf'),
    path('report/export/doc/', views.export_complaints_doc, name='export_complaints_doc'),
    path('report/export/excel/', views.export_complaints_excel, name='export_complaints_excel'),
    path('report/user-complaints/', views.user_complaint_list_view, name='user_complaint_list'),
    path('report/export/user-complaints/pdf/', views.export_user_complaints_pdf, name='export_user_complaints_pdf'),
    path('export/user-complaints/doc/', views.export_user_complaints_doc, name='export_user_complaints_doc'),
    path('export/user-complaints/excel/', views.export_user_complaints_excel, name='export_user_complaints_excel'),
    # Export individual complaint
    path('report/complaint/<int:pk>/export/pdf/', views.export_single_complaint_pdf, name='export_single_complaint_pdf'),
    path('report/complaint/<int:pk>/export/doc/', views.export_single_complaint_doc, name='export_single_complaint_doc'),
    path('report/complaint/<int:pk>/export/excel/', views.export_single_complaint_excel, name='export_single_complaint_excel'),
    # suspect list and detail views
    path('report/suspects/', views.suspect_list, name='suspect_list'),
    path('report/suspects/<int:pk>/', views.suspect_detail_list, name='suspect_detail_list'),
    # Export suspect
    path('report/suspects/export/pdf/', views.export_suspects_pdf, name='export_suspects_pdf'),
    path('report/suspects/export/excel/', views.export_suspects_excel, name='export_suspects_excel'),
    path('report/suspects/export/word/', views.export_suspects_word, name='export_suspects_word'),
    # criminal list and detail views
    path('report/criminal-list/', views.criminal_list, name='criminal_list'),
    path('report/criminal/<int:pk>/', views.criminal_detail, name='criminal_detail'),
    # Export URLs
    path('export/criminals/pdf/', views.export_criminals_pdf, name='export_criminals_pdf'),
    path('export/criminals/excel/', views.export_criminals_excel, name='export_criminals_excel'),
    path('export/criminals/word/', views.export_criminals_word, name='export_criminals_word'),

    path('query/', views.query_menu, name='query_menu'),
    path('help/', views.help_menu, name='help_menu'),

    # Password reset paths
    path('password-reset/', auth_views.PasswordResetView.as_view(template_name='core/password_reset.html'), name='password_reset'),
    path('password-reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='core/password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='core/password_reset_confirm.html'), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='core/password_reset_complete.html'), name='password_reset_complete'),

     # Password Change
    path('password_change/', auth_views.PasswordChangeView.as_view(template_name='core/password_change.html'), name='password_change'),
    path('password_change/done/', auth_views.PasswordChangeDoneView.as_view(template_name='core/password_change_done.html'), name='password_change_done'),

       # Password Reset (Request)
    path('password_reset/', auth_views.PasswordResetView.as_view(template_name='core/password_forgot.html'), name='password_forgot'),

    # Password Reset Done (Instruction Sent)
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='core/password_forgot_done.html'), name='password_forgot_done'),

    # Password Reset Confirm (Link Clicked)
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='core/password_forgot_confirm.html'), name='password_forgot_confirm'),

    # Password Reset Complete (Password Successfully Changed)
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='core/password_forgot_complete.html'), name='password_forgot_complete'),

    path('crime-autocomplete/', views.crime_autocomplete, name='crime_autocomplete'),
]


