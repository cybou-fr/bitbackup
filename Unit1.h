#ifndef Unit1H
#define Unit1H

#include <System.Classes.hpp>
#include <FMX.Controls.hpp>
#include <FMX.Forms.hpp>
#include <FMX.Layouts.hpp>
#include <FMX.Objects.hpp>
#include <FMX.StdCtrls.hpp>

class TUnlockFrame;
class TSetupFrame;
class TOverviewFrame;

class TForm1 : public TForm
{
__published:
    TRectangle *Sidebar;
    TLabel *BrandLabel;
    TLabel *BrandSubtitle;
    TRectangle *NavOverview;
    TLabel *NavOverviewLabel;
    TRectangle *NavSetup;
    TLabel *NavSetupLabel;
    TRectangle *NavIdentity;
    TLabel *NavIdentityLabel;
    TRectangle *NavStorage;
    TLabel *NavStorageLabel;
    TRectangle *NavSources;
    TLabel *NavSourcesLabel;
    TRectangle *NavRestore;
    TLabel *NavRestoreLabel;
    TRectangle *Topbar;
    TLabel *SessionStatusLabel;
    TLayout *ContentHost;
    void __fastcall FormCreate(TObject *Sender);
    void __fastcall FormResize(TObject *Sender);
    void __fastcall NavOverviewClick(TObject *Sender);
    void __fastcall NavSetupClick(TObject *Sender);
    void __fastcall NavLockedClick(TObject *Sender);
private:
    TUnlockFrame *FUnlockFrame;
    TSetupFrame *FSetupFrame;
    TOverviewFrame *FOverviewFrame;
    bool FUnlocked;
    void __fastcall HandleUnlocked(TObject *Sender);
    void ShowFrame(TFrame *frame);
    void SelectNavigation(TRectangle *selected);
    void UpdateResponsiveLayout();
public:
    __fastcall TForm1(TComponent* Owner);
};

extern PACKAGE TForm1 *Form1;
#endif
