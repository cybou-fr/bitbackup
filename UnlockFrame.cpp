#include <fmx.h>
#pragma hdrstop
#include "UnlockFrame.h"
#include <FMX.Platform.hpp>
#include <System.Rtti.hpp>

#pragma package(smart_init)
#pragma resource "*.fmx"

__fastcall TUnlockFrame::TUnlockFrame(TComponent *Owner)
    : TFrame(Owner), FGeneratedMnemonic(false)
{
    CopyButton->Opacity = 0.45f;
    CopyButton->HitTest = false;
}

bool TUnlockFrame::TryReadClipboard(UnicodeString &value)
{
    Fmx::Platform::_di_IFMXClipboardService service;
    if (!TPlatformServices::Current->SupportsPlatformService(__uuidof(IFMXClipboardService), &service))
        return false;
    TValue data = service->GetClipboard();
    if (!data.IsType<UnicodeString>()) return false;
    value = data.AsType<UnicodeString>();
    return true;
}

bool TUnlockFrame::TryWriteClipboard(const UnicodeString &value)
{
    Fmx::Platform::_di_IFMXClipboardService service;
    if (!TPlatformServices::Current->SupportsPlatformService(__uuidof(IFMXClipboardService), &service))
        return false;
    service->SetClipboard(TValue::From<UnicodeString>(value));
    return true;
}

void TUnlockFrame::SetGeneratedMnemonic(const UnicodeString &value)
{
    MnemonicEdit->Text = value.Trim();
    MnemonicEdit->Password = true;
    RevealButtonLabel->Text = L"Reveal";
    FGeneratedMnemonic = !MnemonicEdit->Text.IsEmpty();
    CopyButton->Opacity = FGeneratedMnemonic ? 1.0f : 0.45f;
    CopyButton->HitTest = FGeneratedMnemonic;
    MnemonicHint->Text = FGeneratedMnemonic
        ? L"Generated phrase is hidden. Reveal it and write it down offline."
        : L"The mnemonic is never persisted by the application.";
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
    MnemonicHint->Text = L"Core integration pending; no secret was generated.";
    MnemonicHint->TextSettings->FontColor = 0xFFF2BD5C;
}

void __fastcall TUnlockFrame::RevealClick(TObject *Sender)
{
    MnemonicEdit->Password = !MnemonicEdit->Password;
    RevealButtonLabel->Text = MnemonicEdit->Password ? L"Reveal" : L"Hide";
}

void __fastcall TUnlockFrame::PasteClick(TObject *Sender)
{
    UnicodeString value;
    if (TryReadClipboard(value) && !value.Trim().IsEmpty()) {
        MnemonicEdit->Text = value.Trim();
        FGeneratedMnemonic = false;
        CopyButton->Opacity = 0.45f;
        CopyButton->HitTest = false;
        MnemonicHint->Text = L"Phrase pasted for this session only.";
        MnemonicHint->TextSettings->FontColor = 0xFF5CDB9B;
    } else {
        MnemonicHint->Text = L"Clipboard does not contain text.";
        MnemonicHint->TextSettings->FontColor = 0xFFFF667A;
    }
}

void __fastcall TUnlockFrame::CopyClick(TObject *Sender)
{
    if (!FGeneratedMnemonic || MnemonicEdit->Text.IsEmpty()) return;
    if (TryWriteClipboard(MnemonicEdit->Text)) {
        FCopiedMnemonic = MnemonicEdit->Text;
        ClipboardTimer->Enabled = true;
        MnemonicHint->Text = L"Copied. Clipboard will be cleared in 30 seconds.";
        MnemonicHint->TextSettings->FontColor = 0xFFF2BD5C;
    }
}

void __fastcall TUnlockFrame::ClipboardTimerTimer(TObject *Sender)
{
    ClipboardTimer->Enabled = false;
    UnicodeString current;
    if (TryReadClipboard(current) && current == FCopiedMnemonic)
        TryWriteClipboard(L"");
    FCopiedMnemonic = L"";
    MnemonicHint->Text = L"Clipboard cleared.";
    MnemonicHint->TextSettings->FontColor = 0xFF657188;
}
