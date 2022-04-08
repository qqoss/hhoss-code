package com.hhoss.util.crypto;

import java.util.HashSet;
import java.util.Scanner;
import java.util.Stack;

public class PlayfairCoder{ 
 
    public static int checkChar(char c){ 
 
        if(c>='A'&&c<='Y') 
 
            return 1; 
 
        else 
 
            return 0;    
 
    } 
 
    /* 
 
     *格式化密钥材料 
 
     */ 
 
    public static String formatKey(String key){ 
 
        StringBuffer sb=new StringBuffer(); 
 
        HashSet<Character> hs=new HashSet<Character>(); 
 
        char n; 
 
        String k=key.toUpperCase(); 
 
        char[] detail=new char[25]; 
 
                for(int i=0,j=65;i<25;i++,j++) 
 
                        detail[i]=(char)j; 
 
        for(int i=0;i<k.length();i++){ 
 
            n=k.charAt(i); 
 
            if(!hs.contains(n)&&checkChar(n)==1){ 
 
                sb.append(n); 
 
                hs.add(n); 
 
            } 
 
        } 
 
        int i=0; 
 
        while(sb.length()!=25){ 
 
            char t=detail[i]; 
 
            if(!hs.contains(t)){ 
 
                sb.append(t); 
 
                hs.add(t); 
 
            } 
 
            i++; 
 
        } 
 
        return sb.toString(); 
 
    } 
 
    /* 
 
     *生成密钥矩阵 
 
     */ 
 
    public static char[][] initKey(String k){ 
 
        char[][] key=new char[5][5]; 
 
        String s=formatKey(k); 
 
        int m=0; 
 
        for(int i=0;i<5;i++) 
 
            for(int j=0;j<5;j++){ 
 
                key[i][j]=s.charAt(m); 
 
                m++; 
 
        } 
 
        return key; 
 
    } 
 
    /* 
 
         *格式化明文 
 
         */ 
 
    public static String formatData(String data,String sign){ 
 
        String updata=data.toUpperCase(); 
 
        String ming="",temp=""; 
 
        char c; 
 
        Stack<Character> stack=new Stack<Character>(); 
 
        for(int i=0;i<updata.length();i++){ 
 
            c=updata.charAt(i); 
 
            if(checkChar(c)==1){ 
 
                if(stack.size()%2!=0){ 
 
                    if(stack.peek()==c){ 
 
                        stack.push(sign.charAt(0)); 
 
                        stack.push(c); 
 
                    } 
 
                    else 
 
                        stack.push(c); 
 
                } 
 
                else 
 
                    stack.push(c); 
 
            } 
 
        } 
 
        while(stack.size()>0) 
 
            temp+=stack.pop(); 
 
        for(int i=temp.length()-1;i>-1;i--) 
 
            ming+=temp.charAt(i); 
 
        if(ming.length()%2!=0) 
 
            ming+=sign.charAt(0);    
 
        return ming; 
 
    } 
 
    public static String getEnData(char a,char b,char[][] k){ 
 
        String result=""; 
 
        int h=0,l=0,m=0,n=0; 
 
        for(int i=0;i<k.length;i++) 
 
            for(int j=0;j<k[i].length;j++){ 
 
                if(a==k[i][j]){ 
 
                    h=i; 
 
                    l=j; 
 
                } 
 
                if(b==k[i][j]){ 
 
                    m=i; 
 
                    n=j; 
 
                } 
 
        } 
 
        if(h!=m&&l!=n) 
 
            result=result+k[h][n]+k[m][l]; 
 
        else if(h==m){ 
 
            if(l==4) 
 
                result=result+k[h][0]+k[h][n+1]; 
 
            else if(n==4) 
 
                result=result+k[h][l+1]+k[h][0]; 
 
            else 
 
                result=result+k[h][l+1]+k[h][n+1]; 
 
        } 
 
        else if(l==n){ 
 
            if(h==4) 
 
                                result=result+k[0][l]+k[m+1][l]; 
 
                        else if(m==4) 
 
                                result=result+k[h+1][l]+k[0][l]; 
 
                        else 
 
                                result=result+k[h+1][l]+k[m+1][l]; 
 
                } 
 
        return result; 
 
    } 
 
    public static String getDeData(char a,char b,char[][] k){ 
 
        String result=""; 
 
                int h=0,l=0,m=0,n=0; 
 
                for(int i=0;i<k.length;i++) 
 
                        for(int j=0;j<k[i].length;j++){ 
 
                                if(a==k[i][j]){ 
 
                                        h=i; 
 
                                        l=j; 
 
                                } 
 
                                if(b==k[i][j]){ 
 
                                        m=i; 
 
                                        n=j; 
 
                                } 
 
                } 
 
                if(h!=m&&l!=n) 
 
                        result=result+k[h][n]+k[m][l]; 
 
                else if(h==m){ 
 
                        if(l==0) 
 
                                result=result+k[h][4]+k[h][n-1]; 
 
                        else if(n==0) 
 
                                result=result+k[h][l-1]+k[h][4]; 
 
                        else 
 
                                result=result+k[h][l-1]+k[h][n-1]; 
 
                } 
 
                else if(l==n){ 
 
                        if(h==0) 
 
                                result=result+k[4][l]+k[m-1][l]; 
 
                        else if(m==0) 
 
                                result=result+k[h-1][l]+k[4][l]; 
 
                        else 
 
                                result=result+k[h-1][l]+k[m-1][l]; 
 
                } 
 
                return result; 
 
    } 
 
    /* 
 
     *加密 
 
     */ 
 
    public static String encrypt(String key,String data,String sign){ 
 
        char[][] k=initKey(key); 
 
        String d=formatData(data,sign); 
 
        String endata=""; 
 
        int i=0,j=1; 
 
        char a,b; 
 
        while(j<d.length()){ 
 
            a=d.charAt(i); 
 
            b=d.charAt(j); 
 
            endata=endata+getEnData(a,b,k); 
 
            i+=2; 
 
            j+=2; 
 
        }    
 
        return endata; 
 
    } 
 
    /* 
 
     *解密 
 
     */ 
 
    public static String decrypt(String key,String data,String sign){ 
 
        char[][] k=initKey(key); 
 
        String dedata=""; 
 
        int i=0,j=1; 
 
        char a,b; 
 
        while(j<data.length()){ 
 
            a=data.charAt(i); 
 
            b=data.charAt(j); 
 
            dedata=dedata+getDeData(a,b,k); 
 
            i+=2; 
 
            j+=2; 
 
        } 
 
        dedata=dedata.replaceAll(sign,""); 
 
        return dedata; 
 
    }                    
 
    public static void main(String[] str){ 
 
        Scanner sc=new Scanner(System.in); 
 
        System.out.print("请输入密钥: "); 
 
        String arr=sc.nextLine(); 
 
        System.out.print("请输入明文: "); 
 
        String m=sc.nextLine(); 
 
        System.out.print("请输入标志字符"); 
 
        String sign=sc.nextLine().toUpperCase(); 
 
        String t=formatData(m,sign); 
 
        System.out.println("明文格式化: "+t+"\n密钥矩阵:"); 
 
        char[][] testarr=initKey(arr); 
 
        for(int i=0;i<5;i++) 
 
            for(int j=0;j<5;j++){ 
 
                System.out.print(testarr[i][j]+"   "); 
 
                if(j==4) 
 
                System.out.println(""); 
 
        } 
 
        String jia=encrypt(arr,m,sign); 
 
        System.out.println("加密后: "+jia); 
 
        System.out.println("解密后: "+decrypt(arr,jia,sign)); 
 
     
 
    } 
 
} 
