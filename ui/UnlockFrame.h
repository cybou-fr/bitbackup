#ifndef UnlockFrameH
#define UnlockFrameH

#include <System.Classes.hpp>
#include <FMX.Forms.hpp>
#include <FMX.Layouts.hpp>
#include <FMX.Objects.hpp>
#include <FMX.StdCtrls.hpp>
#include <FMX.Edit.hpp>

class TUnlockFrame : public TFrame
{
__published:
    TRectangle *Background;
    TLayout *Card;
    TLabel *EyebrowLabel;
    TLabel *TitleLabel;
    TLabel *DescriptionLabel;
    TRectangle *MnemonicPanel;
    TEdit *MnemonicEdit;
    TLabel *MnemonicHint;
    TRectangle *ContinueButton;
    TLabel *ContinueButtonLabel;
    TRectangle *GenerateButton;
    TLabel *GenerateButtonLabel;
    TLabel *SecurityNote;
    void __fastcall ContinueClick(TObject *Sender);
    void __fastcall GenerateClick(TObject *Sender);
private:
    TNotifyEvent FOnUnlocked;
public:
    __fastcall TUnlockFrame(TComponent *Owner);
    __property TNotifyEvent OnUnlocked = {read=FOnUnlocked, write=FOnUnlocked};
};

#endif
