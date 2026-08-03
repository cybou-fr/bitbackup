#include <fmx.h>
#pragma hdrstop
#include "SetupFrame.h"

#pragma package(smart_init)
#pragma resource "*.fmx"

__fastcall TSetupFrame::TSetupFrame(TComponent *Owner)
    : TFrame(Owner), FStorageConfigured(false), FFolderConfigured(false)
{
    UpdateReadyState();
}

void __fastcall TSetupFrame::AddStorageClick(TObject *Sender)
{
    FStorageConfigured = true;
    StorageValue->Text = L"Local storage configured · D:\\BitBackupVault";
    StorageValue->TextSettings->FontColor = 0xFF5CDB9B;
    StorageButtonLabel->Text = L"Change";
    UpdateReadyState();
}

void __fastcall TSetupFrame::AddFolderClick(TObject *Sender)
{
    FFolderConfigured = true;
    SourcesValue->Text = L"Documents · root label: Personal";
    SourcesValue->TextSettings->FontColor = 0xFF5CDB9B;
    SourcesButtonLabel->Text = L"Add another";
    UpdateReadyState();
}

void TSetupFrame::UpdateReadyState()
{
    const bool ready = FStorageConfigured && FFolderConfigured;
    FinishButton->Opacity = ready ? 1.0f : 0.45f;
    FinishButton->HitTest = ready;
    FinishButtonLabel->Text = ready ? L"Finish setup" : L"Complete required steps";
}

void __fastcall TSetupFrame::FinishClick(TObject *Sender)
{
    if (FStorageConfigured && FFolderConfigured && FOnSetupComplete)
        FOnSetupComplete(this);
}
