//---------------------------------------------------------------------------

#include <fmx.h>
#ifdef _WIN32
#include <tchar.h>
#endif
#pragma hdrstop
#include <System.StartUpCopy.hpp>
//---------------------------------------------------------------------------
USEFORM("Unit1.cpp", Form1);
USEFORM("ui\\UnlockFrame.cpp", UnlockFrame);
USEFORM("ui\\SetupFrame.cpp", SetupFrame);
USEFORM("ui\\OverviewFrame.cpp", OverviewFrame);
USEFORM("ui\\StorageDialog.cpp", StorageDialogForm);
USEUNIT("ui\\AppConfig.cpp");
//---------------------------------------------------------------------------
extern "C" int FMXmain()
{
	try
	{
		Application->Initialize();
		Application->CreateForm(__classid(TForm1), &Form1);
		Application->Run();
	}
	catch (Exception &exception)
	{
		Application->ShowException(&exception);
	}
	catch (...)
	{
		try
		{
			throw Exception("");
		}
		catch (Exception &exception)
		{
			Application->ShowException(&exception);
		}
	}
	return 0;
}
//---------------------------------------------------------------------------
