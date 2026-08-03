#include <fmx.h>
#pragma hdrstop
#include <FMX.Dialogs.hpp>
#include <System.SysUtils.hpp>
#include "SetupFrame.h"
#include "StorageDialog.h"
#include "AppConfig.h"

#pragma package(smart_init)
#pragma resource "*.fmx"

__fastcall TSetupFrame::TSetupFrame(TComponent *Owner)
    : TFrame(Owner), FStorageConfigured(false), FFolderConfigured(false), FFolderCount(0)
{
    UpdateReadyState();
}

void TSetupFrame::LoadConfiguration()
{
    ClearConfiguration();
    TAppConfig &config = TAppConfig::Instance();
    if (config.HasStorage) {
        FStorageConfigured = true;
        StorageValue->Text = config.Storage.Name + L" - " + config.Storage.Type + L" - " + config.Storage.Location;
        StorageValue->TextSettings->FontColor = 0xFF5CDB9B;
        StorageButtonLabel->Text = L"Change";
    }
    for (const auto &folder : config.Folders) {
        TListBoxItem *item = new TListBoxItem(SourcesList);
        item->Parent = SourcesList; item->Height = 34;
        item->Text = folder.RootLabel + L" - " + folder.Path + L" - root label: " + folder.RootLabel;
        ++FFolderCount;
    }
    FFolderConfigured = FFolderCount > 0;
    if (FFolderConfigured) {
        SourcesValue->Text = IntToStr(FFolderCount) + (FFolderCount == 1 ? L" folder configured" : L" folders configured");
        SourcesValue->TextSettings->FontColor = 0xFF5CDB9B;
        SourcesButtonLabel->Text = L"Add another";
    }
    UpdateReadyState();
}

void TSetupFrame::ClearConfiguration()
{
    SourcesList->Clear();
    FStorageConfigured = false;
    FFolderConfigured = false;
    FFolderCount = 0;
    StorageValue->Text = L"Not configured";
    SourcesValue->Text = L"No folders configured";
    StorageButtonLabel->Text = L"Configure";
    SourcesButtonLabel->Text = L"Add folder";
    UpdateReadyState();
}

void __fastcall TSetupFrame::AddStorageClick(TObject *Sender)
{
    TStorageDialogForm *dialog = new TStorageDialogForm(this);
    try {
        if (dialog->Execute()) {
            FStorageConfigured = true;
            StorageValue->Text = dialog->DisplayName() + L" - " + dialog->StorageType() +
                L" - " + dialog->Location();
            StorageValue->TextSettings->FontColor = 0xFF5CDB9B;
            StorageButtonLabel->Text = L"Change";
            TAppConfig &config = TAppConfig::Instance();
            config.HasStorage = true;
            config.Storage = {dialog->StorageType(), dialog->DisplayName(), dialog->Location(),
                              dialog->User(), dialog->Secret()};
            if (!config.Save())
                ShowMessage(L"Configuration could not be saved. Check access to the local app-data folder.");
            UpdateReadyState();
        }
    }
    __finally {
        delete dialog;
    }
}

void __fastcall TSetupFrame::AddFolderClick(TObject *Sender)
{
    UnicodeString directory;
    if (SelectDirectory(L"Choose a folder to protect", L"", directory)) {
        UnicodeString rootLabel = ExtractFileName(ExcludeTrailingPathDelimiter(directory));
        if (rootLabel.IsEmpty()) rootLabel = L"Root";
        FFolderConfigured = true;
        ++FFolderCount;
        TListBoxItem *item = new TListBoxItem(SourcesList);
        item->Parent = SourcesList;
        item->Text = rootLabel + L" - " + directory + L" - root label: " + rootLabel;
        item->Height = 34;
        SourcesValue->Text = IntToStr(FFolderCount) +
            (FFolderCount == 1 ? L" folder configured" : L" folders configured");
        SourcesValue->TextSettings->FontColor = 0xFF5CDB9B;
        SourcesButtonLabel->Text = L"Add another";
        TAppConfig &config = TAppConfig::Instance();
        config.Folders.push_back({directory, rootLabel});
        if (!config.Save())
            ShowMessage(L"Configuration could not be saved. Check access to the local app-data folder.");
        UpdateReadyState();
    }
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
