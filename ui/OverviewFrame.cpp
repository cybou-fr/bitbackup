#include <fmx.h>
#pragma hdrstop
#include "OverviewFrame.h"

#pragma package(smart_init)
#pragma resource "*.fmx"

__fastcall TOverviewFrame::TOverviewFrame(TComponent *Owner) : TFrame(Owner)
{
}

void __fastcall TOverviewFrame::RunBackupClick(TObject *Sender)
{
    RunButtonLabel->Text = L"Indexing storage…";
    FolderState->Text = L"Preparing";
    FolderState->TextSettings->FontColor = 0xFFF2BD5C;
}
