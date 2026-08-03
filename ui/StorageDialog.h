#ifndef StorageDialogH
#define StorageDialogH

#include <System.Classes.hpp>
#include <FMX.Forms.hpp>
#include <FMX.Layouts.hpp>
#include <FMX.Objects.hpp>
#include <FMX.StdCtrls.hpp>
#include <FMX.Edit.hpp>
#include <FMX.ListBox.hpp>

class TStorageDialogForm : public TForm
{
__published:
    TRectangle *Background;
    TLabel *TitleLabel;
    TLabel *DescriptionLabel;
    TLabel *TypeLabel;
    TComboBox *StorageTypeCombo;
    TListBoxItem *LocalItem;
    TListBoxItem *S3Item;
    TListBoxItem *SftpItem;
    TListBoxItem *FtpItem;
    TLabel *NameLabel;
    TEdit *DisplayNameEdit;
    TLabel *LocationLabel;
    TEdit *LocationEdit;
    TRectangle *BrowseButton;
    TLabel *BrowseButtonLabel;
    TLabel *CredentialsLabel;
    TEdit *UserEdit;
    TEdit *SecretEdit;
    TLabel *HintLabel;
    TRectangle *CancelButton;
    TLabel *CancelButtonLabel;
    TRectangle *SaveButton;
    TLabel *SaveButtonLabel;
    void __fastcall FormCreate(TObject *Sender);
    void __fastcall StorageTypeChange(TObject *Sender);
    void __fastcall BrowseClick(TObject *Sender);
    void __fastcall CancelClick(TObject *Sender);
    void __fastcall SaveClick(TObject *Sender);
private:
    void UpdateFields();
public:
    __fastcall TStorageDialogForm(TComponent *Owner);
    bool Execute();
    UnicodeString StorageType() const;
    UnicodeString DisplayName() const;
    UnicodeString Location() const;
};

#endif
