#ifndef UnlockFrameH
#define UnlockFrameH

#include <System.Classes.hpp>
#include <FMX.Forms.hpp>
#include <FMX.Layouts.hpp>
#include <FMX.Objects.hpp>
#include <FMX.StdCtrls.hpp>
#include <FMX.Edit.hpp>
#include <FMX.Types.hpp>

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
    TRectangle *RevealButton;
    TLabel *RevealButtonLabel;
    TRectangle *PasteButton;
    TLabel *PasteButtonLabel;
    TRectangle *CopyButton;
    TLabel *CopyButtonLabel;
    TTimer *ClipboardTimer;
    TRectangle *ContinueButton;
    TLabel *ContinueButtonLabel;
    TRectangle *GenerateButton;
    TLabel *GenerateButtonLabel;
    TLabel *SecurityNote;
    void __fastcall ContinueClick(TObject *Sender);
    void __fastcall GenerateClick(TObject *Sender);
    void __fastcall RevealClick(TObject *Sender);
    void __fastcall PasteClick(TObject *Sender);
    void __fastcall CopyClick(TObject *Sender);
    void __fastcall ClipboardTimerTimer(TObject *Sender);
private:
    TNotifyEvent FOnUnlocked;
    UnicodeString FCopiedMnemonic;
    bool FGeneratedMnemonic;
    bool TryReadClipboard(UnicodeString &value);
    bool TryWriteClipboard(const UnicodeString &value);
public:
    __fastcall TUnlockFrame(TComponent *Owner);
    void SetGeneratedMnemonic(const UnicodeString &value);
    __property TNotifyEvent OnUnlocked = {read=FOnUnlocked, write=FOnUnlocked};
};

#endif
