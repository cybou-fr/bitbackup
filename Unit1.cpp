#include <fmx.h>
#pragma hdrstop

#include "Unit1.h"
#include "UnlockFrame.h"
#include "SetupFrame.h"
#include "OverviewFrame.h"

#pragma package(smart_init)
#pragma resource "*.fmx"
TForm1 *Form1;

__fastcall TForm1::TForm1(TComponent* Owner) : TForm(Owner)
{
}

void __fastcall TForm1::FormCreate(TObject *Sender)
{
    FUnlockFrame = new TUnlockFrame(this);
    FUnlockFrame->Parent = ContentHost;
    FUnlockFrame->Align = TAlignLayout::Client;

    FSetupFrame = new TSetupFrame(this);
    FSetupFrame->Parent = ContentHost;
    FSetupFrame->Align = TAlignLayout::Client;

    FOverviewFrame = new TOverviewFrame(this);
    FOverviewFrame->Parent = ContentHost;
    FOverviewFrame->Align = TAlignLayout::Client;

    FUnlockFrame->OnUnlocked = NavSetupClick;
    FSetupFrame->OnSetupComplete = NavOverviewClick;
    ShowFrame(FUnlockFrame);
    SelectNavigation(nullptr);
    UpdateResponsiveLayout();
}

void TForm1::ShowFrame(TFrame *frame)
{
    FUnlockFrame->Visible = frame == FUnlockFrame;
    FSetupFrame->Visible = frame == FSetupFrame;
    FOverviewFrame->Visible = frame == FOverviewFrame;
    frame->BringToFront();
}

void TForm1::SelectNavigation(TRectangle *selected)
{
    TRectangle *items[] = { NavOverview, NavSetup, NavIdentity, NavStorage, NavSources, NavRestore };
    for (TRectangle *item : items)
        item->Fill->Color = item == selected ? 0xFF1A2740 : 0xFF080C13;
}

void __fastcall TForm1::NavOverviewClick(TObject *Sender)
{
    ShowFrame(FOverviewFrame);
    SelectNavigation(NavOverview);
    SessionStatusLabel->Text = L"●  Identity unlocked     |     Configuration ready";
}

void __fastcall TForm1::NavSetupClick(TObject *Sender)
{
    ShowFrame(FSetupFrame);
    SelectNavigation(NavSetup);
    SessionStatusLabel->Text = L"●  Identity unlocked     |     Setup required";
}

void __fastcall TForm1::NavLockedClick(TObject *Sender)
{
    ShowFrame(FUnlockFrame);
    SelectNavigation(nullptr);
    SessionStatusLabel->Text = L"●  Locked     |     Mnemonic required";
}

void __fastcall TForm1::FormResize(TObject *Sender)
{
    UpdateResponsiveLayout();
}

void TForm1::UpdateResponsiveLayout()
{
    if (!Sidebar) return;
    Sidebar->Width = ClientWidth < 920 ? 184 : 210;
    BrandSubtitle->Visible = ClientHeight >= 600;
}
