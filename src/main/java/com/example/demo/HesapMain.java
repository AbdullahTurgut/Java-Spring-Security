package com.example.demo;

public class HesapMain {
    public static void main(String[] args) {
        int x,y,z;
        int toplamKanatPuan = KanatHesap(1051,829,643);
        System.out.println(toplamKanatPuan);
    }
    static int KanatHesap(int x,int y,int z){
        return (x*10) + (y*30)+(z*100);
    }
}
