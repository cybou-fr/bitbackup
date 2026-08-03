#ifndef BBComponentsH
#define BBComponentsH

#include <System.Classes.hpp>
#include <FMX.Controls.hpp>
#include <FMX.Layouts.hpp>
#include <FMX.Objects.hpp>
#include <FMX.StdCtrls.hpp>
#include "BBTheme.h"

class TBBButton : public TRectangle
{
private:
    TLabel *FLabel;
    void __fastcall HandleEnter(TObject *Sender)
    {
        Fill->Color = BBTheme::AccentHover;
    }
    void __fastcall HandleLeave(TObject *Sender)
    {
        Fill->Color = BBTheme::Accent;
    }
public:
    __fastcall TBBButton(TComponent *Owner) : TRectangle(Owner)
    {
        Height = 51;
        Width = 242;
        XRadius = 9;
        YRadius = 9;
        Fill->Color = BBTheme::Accent;
        Stroke->Kind = TBrushKind::None;
        Cursor = crHandPoint;
        OnMouseEnter = HandleEnter;
        OnMouseLeave = HandleLeave;

        FLabel = new TLabel(this);
        FLabel->Parent = this;
        FLabel->Align = TAlignLayout::Client;
        FLabel->Text = L"New backup";
        FLabel->TextSettings->HorzAlign = TTextAlign::Center;
        FLabel->TextSettings->VertAlign = TTextAlign::Center;
        FLabel->HitTest = false;
        BBTheme::Label(FLabel, 15, BBTheme::TextPrimary);
    }

    void SetText(const UnicodeString &value) { FLabel->Text = value; }
};

class TBBNavItem : public TRectangle
{
private:
    TLabel *FIcon;
    TLabel *FLabel;
    bool FSelected;
    void __fastcall HandleEnter(TObject *Sender)
    {
        if (!FSelected) Fill->Color = BBTheme::Surface;
    }
    void __fastcall HandleLeave(TObject *Sender)
    {
        if (!FSelected) Fill->Color = BBTheme::Sidebar;
    }
public:
    __fastcall TBBNavItem(TComponent *Owner, const UnicodeString &icon,
        const UnicodeString &caption) : TRectangle(Owner), FSelected(false)
    {
        Height = 46;
        Align = TAlignLayout::Top;
        Margins->Left = 15;
        Margins->Right = 15;
        Margins->Bottom = 7;
        XRadius = 9;
        YRadius = 9;
        Fill->Color = BBTheme::Sidebar;
        Stroke->Kind = TBrushKind::None;
        Cursor = crHandPoint;
        OnMouseEnter = HandleEnter;
        OnMouseLeave = HandleLeave;

        FIcon = new TLabel(this);
        FIcon->Parent = this;
        FIcon->SetBounds(11, 0, 29, Height);
        FIcon->Text = icon;
        FIcon->TextSettings->HorzAlign = TTextAlign::Center;
        FIcon->TextSettings->VertAlign = TTextAlign::Center;
        FIcon->HitTest = false;
        BBTheme::Label(FIcon, 17, BBTheme::TextSecondary);

        FLabel = new TLabel(this);
        FLabel->Parent = this;
        FLabel->SetBounds(46, 0, 126, Height);
        FLabel->Text = caption;
        FLabel->TextSettings->VertAlign = TTextAlign::Center;
        FLabel->HitTest = false;
        BBTheme::Label(FLabel, 13, BBTheme::TextSecondary);
    }

    void SetSelected(bool value)
    {
        FSelected = value;
        Fill->Color = value ? BBTheme::SurfaceHover : BBTheme::Sidebar;
        FIcon->TextSettings->FontColor = value ? BBTheme::TextPrimary : BBTheme::TextSecondary;
        FLabel->TextSettings->FontColor = value ? BBTheme::TextPrimary : BBTheme::TextSecondary;
    }
};

class TBBActivityRow : public TLayout
{
private:
    TRectangle *FStatus;
    TLabel *FMark;
    TLabel *FName;
    TLabel *FDetail;
    TLabel *FTime;
    TRectangle *FDivider;
    void __fastcall HandleResize(TObject *Sender)
    {
        const float timeWidth = Width < 560 ? 108 : 133;
        FTime->Width = timeWidth;
        if (Width < 610) {
            FDetail->Visible = false;
            FName->Width = Width - timeWidth - 54;
        } else {
            FDetail->Visible = true;
            const float detailX = Width * 0.39f;
            FName->Width = detailX - 48;
            FDetail->Position->X = detailX;
            FDetail->Width = Width - detailX - timeWidth - 18;
        }
    }
public:
    __fastcall TBBActivityRow(TComponent *Owner, const UnicodeString &name,
        const UnicodeString &detail, const UnicodeString &time, bool active = false)
        : TLayout(Owner)
    {
        Height = 49;
        Align = TAlignLayout::Top;

        FStatus = new TRectangle(this);
        FStatus->Parent = this;
        FStatus->SetBounds(0, 12, 23, 23);
        FStatus->XRadius = 12;
        FStatus->YRadius = 12;
        FStatus->Fill->Color = active ? BBTheme::Accent : BBTheme::Success;
        FStatus->Stroke->Kind = TBrushKind::None;

        FMark = new TLabel(this);
        FMark->Parent = FStatus;
        FMark->Align = TAlignLayout::Client;
        FMark->Text = active ? L"↑" : L"✓";
        FMark->TextSettings->HorzAlign = TTextAlign::Center;
        FMark->TextSettings->VertAlign = TTextAlign::Center;
        FMark->HitTest = false;
        BBTheme::Label(FMark, 12, active ? BBTheme::TextPrimary : 0xFF07120D);

        FName = new TLabel(this);
        FName->Parent = this;
        FName->SetBounds(38, 0, 223, 48);
        FName->Text = name;
        FName->TextSettings->VertAlign = TTextAlign::Center;
        BBTheme::Label(FName, 12, BBTheme::TextPrimary);

        FDetail = new TLabel(this);
        FDetail->Parent = this;
        FDetail->SetBounds(270, 0, 314, 48);
        FDetail->Text = detail;
        FDetail->TextSettings->VertAlign = TTextAlign::Center;
        BBTheme::Label(FDetail, 11, BBTheme::TextSecondary);

        FTime = new TLabel(this);
        FTime->Parent = this;
        FTime->Align = TAlignLayout::Right;
        FTime->Width = 133;
        FTime->Text = time;
        FTime->TextSettings->HorzAlign = TTextAlign::Trailing;
        FTime->TextSettings->VertAlign = TTextAlign::Center;
        BBTheme::Label(FTime, 11, BBTheme::TextSecondary);

        FDivider = new TRectangle(this);
        FDivider->Parent = this;
        FDivider->Align = TAlignLayout::Bottom;
        FDivider->Height = 1;
        FDivider->Fill->Color = BBTheme::Border;
        FDivider->Stroke->Kind = TBrushKind::None;
        OnResize = HandleResize;
        HandleResize(this);
    }
};

#endif
