#ifndef OverviewFrameH
#define OverviewFrameH

#include <System.Classes.hpp>
#include <FMX.Forms.hpp>
#include <FMX.Layouts.hpp>
#include <FMX.Objects.hpp>
#include <FMX.StdCtrls.hpp>

class TOverviewFrame : public TFrame
{
__published:
    TRectangle *Background;
    TVertScrollBox *Scroll;
    TLayout *Canvas;
    TLabel *TitleLabel;
    TLabel *DescriptionLabel;
    TRectangle *RunButton;
    TLabel *RunButtonLabel;
    TRectangle *IdentityCard;
    TLabel *IdentityTitle;
    TLabel *IdentityStatus;
    TRectangle *StorageCard;
    TLabel *StorageTitle;
    TLabel *StorageStatus;
    TRectangle *FoldersCard;
    TLabel *FoldersTitle;
    TLabel *FoldersStatus;
    TLabel *PlanTitle;
    TRectangle *FolderRow;
    TLabel *FolderName;
    TLabel *FolderPath;
    TLabel *FolderState;
    void __fastcall RunBackupClick(TObject *Sender);
public:
    __fastcall TOverviewFrame(TComponent *Owner);
};

#endif
