#ifndef BBThemeH
#define BBThemeH

#include <System.UITypes.hpp>
#include <FMX.StdCtrls.hpp>

namespace BBTheme
{
    static const TAlphaColor Background = 0xFF090D14;
    static const TAlphaColor Sidebar = 0xFF080C13;
    static const TAlphaColor Topbar = 0xFF0B111A;
    static const TAlphaColor Surface = 0xFF111A27;
    static const TAlphaColor SurfaceHover = 0xFF18243A;
    static const TAlphaColor Border = 0xFF243044;
    static const TAlphaColor TextPrimary = 0xFFF3F6FB;
    static const TAlphaColor TextSecondary = 0xFF98A4B7;
    static const TAlphaColor TextMuted = 0xFF657188;
    static const TAlphaColor Accent = 0xFF6675F5;
    static const TAlphaColor AccentHover = 0xFF7886FF;
    static const TAlphaColor Success = 0xFF5CDB9B;
    static const TAlphaColor Warning = 0xFFF2BD5C;

    inline void Label(TLabel *label, float size, TAlphaColor color,
        TFontStyleExt styles = TFontStyleExt())
    {
        label->TextSettings->Font->Family = L"Segoe UI Variable";
        label->TextSettings->Font->Size = size;
        label->TextSettings->FontColor = color;
        label->TextSettings->Font->StyleExt = styles;
        label->StyledSettings = label->StyledSettings
            >> TStyledSetting::Family >> TStyledSetting::Size
            >> TStyledSetting::FontColor >> TStyledSetting::Style;
    }
}

#endif
