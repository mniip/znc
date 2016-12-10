#include <znc/Modules.h>
#include <znc/IRCSock.h>
#include <znc/IRCNetwork.h>
#include <znc/Server.h>

class CSocks4Mod: public CModule
{
private:
	bool isHandshake;
	CString socksResponse;
	VCString sendQueue;
	
	CString ircHostName;
	uint16_t ircPort;
	CString ircPass;
	bool ircSSL;

	CString proxyHostName = "localhost";
	uint16_t proxyPort = 12345;

public:
	MODCONSTRUCTOR(CSocks4Mod)
	{
		isHandshake = false;
	}

	EModRet OnIRCConnecting(CIRCSock *sock)
	{
		CServer *server = GetNetwork()->GetCurrentServer();
		ircHostName = server->GetName();
		ircPort = server->GetPort();
		ircPass = server->GetPass();
		ircSSL = server->IsSSL();
		server->~CServer();
		new(server) CServer(proxyHostName, proxyPort, ircPass, false);
		DEBUG("Spoofing server: " << ircHostName << " -> " << server->GetName() << ", " << ircPort << " -> " << server->GetPort() << ", " << ircSSL << " -> " << server->IsSSL());
		return CONTINUE;
	}

	EModRet OnIRCRegistration(CString &pass, CString &nick, CString &ident, CString &realName)
	{
		CServer *server = GetNetwork()->GetCurrentServer();
		server->~CServer();
		new(server) CServer(ircHostName, ircPort, ircPass, ircSSL);
		DEBUG("Unspoofing server: " << server->GetName() << ", " << server->GetPort() << ", " << server->IsSSL());

		isHandshake = true;
		socksResponse = "";
		sendQueue.empty();

		CString request;
		request.append(1, '\x04'); // SOCKS4
		request.append(1, '\x01'); // connect
		request.append(1, (char)(ircPort >> 8));
		request.append(1, (char)(ircPort & 0xFF));
		request.append("\x00\x00\x00\x01", 4);
		request.append(ident);
		request.append(1, '\x00');
		request.append(ircHostName);
		request.append(1, '\x00');
		GetNetwork()->GetIRCSock()->Write(request);

		return CONTINUE;
	}

	EModRet OnRawData(CString &data)
	{
		if(isHandshake)
		{
			socksResponse += data;
			if(socksResponse.size() >= 8)
			{
				data = socksResponse.substr(8);
				uint8_t code = socksResponse[1];

				socksResponse = "";
				isHandshake = false;
				if(code == 90)
				{
					if(ircSSL)
						GetNetwork()->GetIRCSock()->StartTLS();
					for(CString line : sendQueue)
					{
						DEBUG("Resending: [" << line << "]");
						PutIRC(line);
					}
				}
				else
					PutModule("Proxy connection failed");
				sendQueue.empty();
				return CONTINUE;
			}
			else
				return HALT;
		}
		else
			return CONTINUE;
	}

	EModRet OnSendToIRC(CString &line)
	{
		if(isHandshake)
		{
			sendQueue.push_back(line);
			DEBUG("Not sending: [" << line << "]");
			return HALT;
		}
		else
			return CONTINUE;
	}
};

template<> void TModInfo<CSocks4Mod>(CModInfo &info)
{
    info.SetArgsHelpText("");
}

NETWORKMODULEDEFS(CSocks4Mod, "Connect through a Socks4a proxy.")
