#include <fmx.h>
#pragma hdrstop

#include <FMX.Dialogs.hpp>
#include "StorageDialog.h"

#pragma package(smart_init)
#pragma resource "*.fmx"

__fastcall TStorageDialogForm::TStorageDialogForm(TComponent *Owner) : TForm(Owner)
{
}

void __fastcall TStorageDialogForm::FormCreate(TObject *Sender)
{
    StorageTypeCombo->ItemIndex = 0;
    UpdateFields();
}

void __fastcall TStorageDialogForm::StorageTypeChange(TObject *Sender)
{
    UpdateFields();
}

void TStorageDialogForm::UpdateFields()
{
    const bool local = StorageTypeCombo->ItemIndex == 0;
    LocationLabel->Text = local ? L"Vault folder" : L"Endpoint / host";
    LocationEdit->TextPrompt = local ? L"Choose a local folder or USB drive" : L"Host, bucket or service endpoint";
    BrowseButton->Visible = local;
    CredentialsLabel->Visible = !local;
    UserEdit->Visible = !local;
    SecretEdit->Visible = !local;
    HintLabel->Text = local
        ? L"The folder will contain encrypted .bbk objects only."
        : L"Credentials remain in the application layer and are never sent to bbcore.";
}

void __fastcall TStorageDialogForm::BrowseClick(TObject *Sender)
{
    UnicodeString directory = LocationEdit->Text;
    if (SelectDirectory(L"Choose BitBackup storage folder", L"", directory))
        LocationEdit->Text = directory;
}

void __fastcall TStorageDialogForm::CancelClick(TObject *Sender)
{
    ModalResult = mrCancel;
}

void __fastcall TStorageDialogForm::SaveClick(TObject *Sender)
{
    if (DisplayNameEdit->Text.Trim().IsEmpty() || LocationEdit->Text.Trim().IsEmpty()) {
        HintLabel->Text = L"Display name and location are required.";
        HintLabel->TextSettings->FontColor = 0xFFFF667A;
        return;
    }
    ModalResult = mrOk;
}

bool TStorageDialogForm::Execute()
{
    return ShowModal() == mrOk;
}

UnicodeString TStorageDialogForm::StorageType() const
{
    return StorageTypeCombo->Selected ? StorageTypeCombo->Selected->Text : L"Local";
}

UnicodeString TStorageDialogForm::DisplayName() const
{
    return DisplayNameEdit->Text.Trim();
}

UnicodeString TStorageDialogForm::Location() const
{
    return LocationEdit->Text.Trim();
}

UnicodeString TStorageDialogForm::User() const
{
    return UserEdit->Text.Trim();
}

UnicodeString TStorageDialogForm::Secret() const
{
    return SecretEdit->Text;
}
