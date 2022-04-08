package com.hhoss.util.crypto;

import java.io.File;

public class RSAHelperTest {

	public static void main(String[] srgs){
		
		try {
			RSAKeyUtil ru = new RSAKeyUtil(new File("/certs/credit2go.p12"),null); 
			
			RSAHelper signHelper = new RSAHelper(ru.getPrivateKey()); 

		} catch (Exception e) {
			e.printStackTrace();
		}

		
	}
	
	private static String getEnc(){
		return 
		 "RTcfi9YwkkEKbtY3iNQCHUXb8UkIXq+PyHB9qRQ5ivfCz4RcrIof6NPCBObFroEw2wpQmVeYUrxZ"
		+"KE5+oK8tLYUXgf599iUdU0Ui1LqDGsEbS6gayAueODYXxx8BYscMpfG4336zyAJ5qnDx+43WP8x6"
		+"RW5a4OUfuS3XkX1OJixeD79pbIHio2H2SVZhIFOr0btkkh7JVAae79PMhQASvVf2LxnsuPLP9vTU"
		+"193nDtmi0XzLn1fdczvE6AsTtan8dkGX1dCMSHtUUwO6U7bCWLBxOQwUSR4lLKVtF1fwgVJIN0yn"
		+"OxSkBNxDpYzMDvgg4LcEmJY/UcUNr4JHTAGGLzwXmzBUeAGD+fEjCFQxbHVAIpGjTUC4BT7gAqlo"
		+"E2s6WKUO/njOXpsIb02ceOEZRZEfkTSaaZeQ1fZ1kbQfP9f4+8hYUz9cN4yofpEe7D4au7rM0F0d"
		+"LzMWE7IUDdPqzZLLXdr97uWIth+M9eAAAZ/WGmpfHAZ5s3CprZvjftwDlMQhLTUqiUsJTnieNW00"
		+"+vq5AAqCGuMQ1ry+g5+EfON+Q6OWICV/nT+QTjHEMrWW4r4snBvFyQY74JzmwqpsCbt72ZtfUGsb"
		+"/jlRyMnTLOoWCW6SoG6q9rGipLSRIEWeNW5WWmTSvW/ZBiET5DJGQ/tdLE2+mURRYRIPmMb9YNQ=";
	}
}
