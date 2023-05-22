#import <Cephei/HBPreferences.h>
#import <NetworkExtension/NWHostEndpoint.h>
#import <objc/runtime.h>
#import "LinkDirectorMessage.h"
#import "NRDDeviceConductor.h"
#import "NRLinkDirector.h"
#import "NWAddressEndpoint.h"
#import "NRLink.h"
#import "NRDLocalDevice.h"
#import "NRDLDKeys.h"

HBPreferences *preferences;
BOOL rerouteEnabled;
BOOL startupComplete = false;
BOOL keyExtractStartupComplete = false;
NSInteger spoofTrigger = 0;
unsigned int targetIP = 0;

%ctor {
    preferences = [[HBPreferences alloc] initWithIdentifier:@"net.rec0de.ios.watchwitch"];
    [preferences registerDefaults:@{
        @"targetIP": @0u
    }];

    [preferences registerBool:&rerouteEnabled default:NO forKey:@"reroute"];
    
    // communicate tweak start time to companion app
    NSDate *date = [NSDate date];
    double timestamp = date.timeIntervalSince1970;
    NSLog(@"WWitch: start time %f", timestamp);
    [preferences setDouble: timestamp forKey:@"tweakStarted"];

    NSLog(@"WWitch: Rerouting enabled? %i", rerouteEnabled);

    NSString *notificationName = @"net.rec0de.ios.watchwitch/ReloadPrefs";
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), (CFNotificationName) notificationName, nil, nil, true);

    // we have to run NRDDeviceConductor code from an appropriate queue for it to work
    dispatch_block_t manualSpoofBlock = dispatch_block_create(DISPATCH_BLOCK_INHERIT_QOS_CLASS, ^{
        NRLinkDirector *director = [objc_getClass("NRLinkDirector") copySharedLinkDirector];

        for (NRDDeviceConductor *conductor in director.conductors.allValues){
            [conductor spoofWifiEndpointToWatch];
        }
    });

    [preferences registerPreferenceChangeBlockForKey:@"spoofTrigger" block:^(NSString *key, id<NSCopying> _Nullable value){
    	// observer block is triggered once on startup, we'll want to ignore that
    	if (!startupComplete){
    		startupComplete = true;
    		return;
    	}

    	NSLog(@"WWitch: spoofTrigger");
    	NRLinkDirector *director = [objc_getClass("NRLinkDirector") copySharedLinkDirector];
        dispatch_async([director queue], manualSpoofBlock);
	}];

	[preferences registerPreferenceChangeBlockForKey:@"targetIP" block:^(NSString *key, id<NSCopying> _Nullable value){
    	NSLog(@"WWitch: Target IP %#010x", (unsigned int) [preferences unsignedIntegerForKey:@"targetIP"]);
	}];

	dispatch_block_t extractKeysBlock = dispatch_block_create(DISPATCH_BLOCK_INHERIT_QOS_CLASS, ^{
        NRLinkDirector *director = [objc_getClass("NRLinkDirector") copySharedLinkDirector];

        //NRDLDKeys *classCKeys = [objc_getClass("NRDLocalDevice") classCKeys];
        //NRDLDKeys *classDKeys = [objc_getClass("NRDLocalDevice") classDKeys];

        //NSData *publicClassA = (NSData *) [classAKeys remotePublicKey];
        //NSData *publicClassC = (NSData *) [classCKeys remotePublicKey];
        //NSData *publicClassD = (NSData *) [classDKeys remotePublicKey];

        //NSLog(@"WWitch: class c public key %@", publicClassC);
        //NSLog(@"WWitch: class d public key %@", publicClassD);

        //NSLog(@"WWitch: %@", [objc_getClass("NRDLocalDevice") copyStatusString]);
        NSUUID *uuid = nil;
  
  		// idk why there can be multiple directors but let's just get one UUID for now
        for (NRDDeviceConductor *conductor in director.conductors.allValues){
        	uuid = conductor.nrUUID;
        }

        NRDLocalDevice *device = [objc_getClass("NRDLocalDevice") copyLocalDeviceForNRUUID:uuid];
        	
        NRDLDKeys *classAKeys = [device copyKeys:0x01];
        NRDLDKeys *classCKeys = [device copyKeys:0x03];
        NRDLDKeys *classDKeys = [device copyKeys:0x04];

        NSData *publicClassA = (NSData *) [classAKeys remotePublicKey];
        NSData *publicClassC = (NSData *) [classCKeys remotePublicKey];
        NSData *publicClassD = (NSData *) [classDKeys remotePublicKey];

        NSData *privateClassA = (NSData *) [classAKeys localPrivateKey];
        NSData *privateClassC = (NSData *) [classCKeys localPrivateKey];
        NSData *privateClassD = (NSData *) [classDKeys localPrivateKey];

        /*NSLog(@"WWitch: class A public: %@", publicClassA);
        NSLog(@"WWitch: class C public: %@", publicClassC);
        NSLog(@"WWitch: class D public: %@", publicClassD);
        NSLog(@"WWitch: class A private: %@", privateClassA);
        NSLog(@"WWitch: class C private: %@", privateClassC);
        NSLog(@"WWitch: class D private: %@", privateClassD);*/

        unsigned char chunk[192];
        memcpy(&chunk, publicClassA.bytes, 32);
        memcpy(&chunk[32], publicClassC.bytes, 32);
        memcpy(&chunk[64], publicClassD.bytes, 32);
        memcpy(&chunk[96], privateClassA.bytes, 32); 
        memcpy(&chunk[128], privateClassC.bytes, 32); 
        memcpy(&chunk[160], privateClassD.bytes, 32); 

        NSString *notificationName = @"net.rec0de.ios.watchwitch/Keys/";
    	CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), (CFNotificationName) notificationName, nil, nil, true);

    });

    [preferences registerPreferenceChangeBlockForKey:@"keyExtractTrigger" block:^(NSString *key, id<NSCopying> _Nullable value){
    	// observer block is triggered once on startup, we'll want to ignore that
    	if (!keyExtractStartupComplete){
    		keyExtractStartupComplete = true;
    		return;
    	}

    	NSLog(@"WWitch: key extract");
    	NRLinkDirector *director = [objc_getClass("NRLinkDirector") copySharedLinkDirector];
        dispatch_async([director queue], extractKeysBlock);
	}];
}

%hook NRDDeviceConductor

-(void)linkDidReceiveData:(id)arg1 data:(id)arg2 {
	NSLog(@"WWitch: linkDidReceiveData");
	%orig;
	/*if (rerouteEnabled){
		[self spoofWifiEndpointToWatch];
	}*/
}

%new
-(void)spoofWifiEndpointToWatch {
	NSLog(@"WWitch: Attempting to spoof WiFi endpoint to watch");

	struct sockaddr_in sadr;
	memset(&sadr, 0, sizeof(sadr));
	sadr.sin_len = sizeof(sadr);
	sadr.sin_family = AF_INET;
	sadr.sin_addr.s_addr = htonl((unsigned int) [preferences unsignedIntegerForKey:@"targetIP"]);

	NWHostEndpoint *endpoint = [objc_getClass("NWAddressEndpoint") endpointWithAddress:(const struct sockaddr*)&sadr];

	NRLinkDirectorMessage *msg = [[objc_getClass("NRLinkDirectorMessage") alloc] initOutgoingDirectorMessageWithNRUUID:self.nrUUID];
	[msg addUpdateWiFiAddressEndpoint:(id)endpoint portHBO:(unsigned short)0x1388];
	[msg send];
}

%end


%hook NRLinkDirectorMessage

-(void)addUpdateWiFiAddressEndpoint:(id)endpoint portHBO:(unsigned short)port {
	// hijack organic address updates to carry our IP instead
	if(rerouteEnabled) {
		NSLog(@"WWitch: Overriding legitimate WiFi Address Update");
		port = 0x1388;
		NWAddressEndpoint *nwe = (NWAddressEndpoint *) endpoint;
		struct sockaddr_in *adr = (struct sockaddr_in *) [nwe address];
		adr->sin_addr.s_addr = htonl((unsigned int) [preferences unsignedIntegerForKey:@"targetIP"]);
	}
	return %orig;
}

-(id)initDirectorMessageWithNRUUID:(NSUUID *) uuid messageLen:(unsigned)arg2 messageVersion:(unsigned char)arg3 {
	NSLog(@"WWitch: init LinkDirectorMessage %@", uuid.UUIDString);
	return %orig;
}

-(id)initOutgoingDirectorMessageWithNRUUID:(NSUUID *)uuid {
	NSLog(@"WWitch: init outgoing LinkDirectorMessage %@", uuid.UUIDString);
	return %orig;
}

%end

/*
%hook NRLinkManagerWiFi

-(void)setPeerWiFiEndpoint:(NWHostEndpoint *)arg1 {
	NSLog(@"WWitch: setPeerWiFiEndpoint %s", arg1.hostname.UTF8String);
	%orig;
}

%end
*/