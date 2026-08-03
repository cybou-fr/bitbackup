#ifndef SetupFrameH
#define SetupFrameH

#include <System.Classes.hpp>
#include <FMX.Forms.hpp>
#include <FMX.Layouts.hpp>
#include <FMX.Objects.hpp>
#include <FMX.StdCtrls.hpp>
#include <FMX.ListBox.hpp>

class TSetupFrame : public TFrame
{
__published:
    TRectangle *Background;
    TVertScrollBox *Scroll;
    TLayout *Canvas;
    TLabel *TitleLabel;
    TLabel *DescriptionLabel;
    TRectangle *IdentityCard;
    TLabel *IdentityStep;
    TLabel *IdentityTitle;
    TLabel *IdentityValue;
    TRectangle *StorageCard;
    TLabel *StorageStep;
    TLabel *StorageTitle;
    TLabel *StorageValue;
    TRectangle *StorageButton;
    TLabel *StorageButtonLabel;
    TRectangle *SourcesCard;
    TLabel *SourcesStep;
    TLabel *SourcesTitle;
    TLabel *SourcesValue;
    TListBox *SourcesList;
    TRectangle *SourcesButton;
    TLabel *SourcesButtonLabel;
    TRectangle *FinishButton;
    TLabel *FinishButtonLabel;
    void __fastcall AddStorageClick(TObject *Sender);
    void __fastcall AddFolderClick(TObject *Sender);
    void __fastcall FinishClick(TObject *Sender);
private:
    TNotifyEvent FOnSetupComplete;
    bool FStorageConfigured;
    bool FFolderConfigured;
    int FFolderCount;
    void UpdateReadyState();
public:
    __fastcall TSetupFrame(TComponent *Owner);
    __property TNotifyEvent OnSetupComplete = {read=FOnSetupComplete, write=FOnSetupComplete};
};

#endif
