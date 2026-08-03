#include <fmx.h>
#pragma hdrstop
#include "UnlockFrame.h"

#pragma package(smart_init)
#pragma resource "*.fmx"

__fastcall TUnlockFrame::TUnlockFrame(TComponent *Owner) : TFrame(Owner)
{
}

void __fastcall TUnlockFrame::ContinueClick(TObject *Sender)
{
    MnemonicHint->Text = MnemonicEdit->Text.Trim().IsEmpty()
        ? L"Enter your 12 or 24 recovery words first."
        : L"Mnemonic accepted for this UI preview.";
    MnemonicHint->TextSettings->FontColor = MnemonicEdit->Text.Trim().IsEmpty()
        ? 0xFFFF667A : 0xFF5CDB9B;
    if (!MnemonicEdit->Text.Trim().IsEmpty() && FOnUnlocked)
        FOnUnlocked(this);
}

void __fastcall TUnlockFrame::GenerateClick(TObject *Sender)
{
    MnemonicEdit->Text = L"Generated mnemonic will appear here when bbcore implements bb_mnemonic_new().";
    MnemonicHint->Text = L"Core integration pending; no secret was generated.";
    MnemonicHint->TextSettings->FontColor = 0xFFF2BD5C;
}
