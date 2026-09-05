from __future__ import annotations

from base64 import b85decode
from copy import deepcopy
from hashlib import sha256
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from zlib import decompress


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[2]
O14 = ROOT.parent / "o14"
CORPUS = REPO / "conformance/application-protocol/c03"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(O14))

from canonical_json import dumps, load, loads  # noqa: E402
from corpus_model import (  # noqa: E402
    DOMAINS,
    ProtocolError,
    ed25519_sign,
    ed25519_verify_detailed,
    evaluate_k_admission_graph,
    framed_hash,
    synthetic_octets,
)
from generate_corpus import _application_vector, _event_fields  # noqa: E402
import h1_h2_relation as relation  # noqa: E402
from h1_h2_relation import (  # noqa: E402
    BASE_SHA,
    MUTANTS,
    RATIFICATION_V4_SHA256,
    RelationError,
    TEP_FILENAMES,
    _parse_v4_authority,
    _parse_v4_structure,
    _clean_checkout,
    _closed_environment,
    _manifest_bytes,
    _resolve_toolchain,
    _validate_candidate_set_wrapper_identities,
    _validate_jsonl,
    _validate_v4_reconstruction,
    _verify_tep_structure,
    run_runtime,
    slot_cases,
    validate_relation,
)
from scenarios import required_witnesses  # noqa: E402


_V4_FIXTURE_B85 = (
    "c-"
    "qZ<+jiSXlHfbO0^9Y_RXYR;fFKE4md>Fl%3@m*wUTUa&5MXjLP8rPH~=VHy*1~|N6h2y&&`)?Trv{?Maix?r`$DXsx6Yp%*e"
    ">NM`Yk9b82_{=2Z}V4(^3DF~!#)s;slw<isq*O2lbUrTN+nR$?8)f0g;sGym&9{?m-"
    "|b(v>r98@AUqhKA=pN4T$1=Y5EV=g~jUQcf4r}Np#-"
    "E?w!GC!Hz&X!%nxP3@V6aK$?5GKqZ%uSJR@)BmL*NB3mNa36C$;{Wn%)hKfVHE&Ll12<ql&|nf1O9xMR%hGLoR{TRn9H(y`f"
    "8OT+7_aRfB)o;M@tjngY5*dS>^WvRxZphY4t!bY}e64u)Y_u0b>eWoo5R3_^E5of+9=d@g^?xZcFo{(=k7~H2ufE859B@d`!"
    "g`12$RZ1%jVF(a-qXI<L%hT~<MsiMRuQMtQNx3qoOD0O|qkDhM+HXj(3pmH1j2(-u&;8-mQdIh$DSVED%L#(fd?-"
    "OzWOfjtOA$MXYc7`x6ejQnWm*!^J;Cbrj)2TmLYV(j}ve;{l-"
    "Nk#*B*!bwwlO>+(Cj)N~#!){Q#f}?$eb@KIs4u*+GfW&23pWmgFB~y&;ED0jjiWfS{edq;7~y1$fd+uiIP80{o*%j}m+v`&a"
    "3gQvM7HC5vF!xGz)l8s?DwPC3+z!p9FM$Y=mrV?=@@`uJy|>mMC97>D2Q=Mdlbh>=s2Uk8};MZ84i;$^2UA?!v5`%EyN&>ZM"
    "#1nhOuXd{SYVH1uz`g(a=t8*B%9a?DXwWcyS-LHtdfgK$+`$p$&ix;a_j$`SD;7xE?G%hOGdi3^;l{*~oQ=!j42Z8hdsk?7l"
    "Z12cu}{#p4kio`@1p3<uE&1_LG>FB<rOm?W^hsP82G2q$|6U?|1_m*Y7w&k)XFkO<NDz0qhi9NV@R`oj17fRZuLK<xQ$FbMi"
    "~Y=<_U&B#Myl8i^}jXYd#H=+Qp10p6GMOMhtN)$n6Mp>{e;fD-"
    "}7)Uc+o4`;+`Yv$9qbQz?oS3N1F+2=eB>*ZngKhPY7b(bt^igziP5I3~VCr=a&jH(~$R!34KS+VcG=@1>+ltw2yROpAOe+O+"
    "_=FsXyu_a$wyR(bv;5muloj%qk*;I00T}`y!H(dMydb%P%um9DMaps&z#d{C>LqNu$hY?o=4oEsi))buPr!RW{bV{_bB^<*R"
    "VvDkSw{IrNGbAnzy-"
    ">@2N8YV<S7Ut!!ob+X5KuPK_K=l^EfC4{03As@}kHYdr|BreliM&eW%}dhyEyV2W|+5=tjbJY0OoT0%}P7nft^a%r_XgL)#e"
    "*hQnp2B^eA87V87?g+tLF*seG9V<6~pV2?v@7>Z%sPr|_vc*5(4@d()7b=*<d2aX>I;N?;14+)5CwPTQf_v^f@(#S;p@CH|i"
    "!^rMO-f-xGoEZ%5zS|#$0Z{V5?}yPSwuO@n$Ajp_nW{nvnkf+pNHX9m5Hvuy1CSK<I2i=VK=>mNA-)s9M*X-"
    "wQ@CBnphFa^;6&rmIQEA2U?4_f6gmCCcM>-M5#)zXG9E`DAAzMKK!z6&hjw5Ofp5e(h=v3Bd+5^wGa|856vpPD>*!-"
    "wnz6;8xT@=q!vI(l*bb%!XvN3{K92^%3BxcJv6tARu@5KUMx#N0;EsW5`+boFqrM#kLspHVrY~A3ElFuK)H5>4I$~Oszpez("
    "u4Xq-"
    "T66d=crrqqZ4;ygtCu(}L9YTNW|l{wg5W`<NuZh{03FydD*<{w%knSq2rv)PHqbtNW#EJ62DlnnA^mD5Mg9+XI8T5eQxF(rL"
    "!dI-mS&P>$T7fJLXgh2NWLsA#{)^S*}{|te6RuRV4be-OJEV$8w^=kwhs$GiVT>oqc?pFWDTbr6s$;Tt>xw7?%iT(!q6u}Yw"
    ")glnVTXLkH8uadJBjqEqP*Pfz-x^QtcpI_`FXo+o=VEWqYi^Hyf}7*lr<!z+%v+@qmcM-Qe?s=HM|MN1O{jD-DPVxB{G?6hQ"
    "*#du>F3DrD{6c7vux2S_}KpE|fKNX8)R@G*C^tj$XhFB(hcamPIC!{c$V0U_QoZcg5J%vh}Qj(M7i`!py`ma_2{2>VN3d}cw"
    "15}jyWDul8ma}PGW35pVTROZ_v5~X3ZwFck;XhLcLtEmB4qr5Q;5TXLLh54m`Z2(lTsejudJzDU!mSzBT6p2j*R4A;dKqZt0"
    "9j$Zx4)B-"
    "$1cZaYO*Sa#ffQ$E9x)Jb40%GwQ?pA12UV3gemQh|jyvpujP1F0&$E{Y2J9Ulm(YP(`+rZFuuC{kQhWeP62RvF>p%V<KmZ?c"
    "mFgj=fCYs32caQHH0X5@IGhv?`956(Z^U`DMLJ`_9RlxtE)R@8FU?${pItsW%bfuMZB&o*y7ks48Y$Di0wAJT(IiFwrAP1p6"
    "XxcZhctR1g)g5S$|+&8!QRPEnv<b6URSTpH>&3wcFp%TjNUvHC@%n?Aag1(bCvQ&t|`c*j|I>Q;<ylrpu+<czd=(2(L&4#`~"
    "~;~ibaXiF_$#OlEg-"
    "7>WRS^&(}am8E6vt0mx?~SL+bNmFfK&JQ83PoDBpEaw%}p35i6JrAVNbA^{qBV2ofRZfheaTi|{mSMkgk!QJRhz~M2Q#~?5O"
    ")Kw@7+!(IS13@ASGWa)zDD^2Tn+e3pYLf$*0kQ$pAdFVqtV%cV$9pS?S7}u#wA7<Zq<aKoA1-"
    "<|Y*8M7Xof$4u5%oK6J_~5jbK<!5EJTP2Y{X=T_ZmHuKsomXaT8P36h<}3V34oj2c)ss-"
    "#8PAT4rgN^@eJz!6uB4Ebn_SLAb>4D?7%Vx<X!&Fh%M4iX!n+&{p7jPVXsaIhI2Rzj0)SPCHPf+!2_;fO)t0{%1LXfgyFR4k"
    "`-?0QZg=2XV01@_+){8E|A{{se3CwJ_BUv?xjppq-=AK*Xl-"
    "<P;ab~0Ih)^_a%d8;Cy57ERtv4p|O1fZ|id9fnPc~=gbpfGmLLExk}Xoa@z@#nlvM_?vE`7N}ATtunC^z7OII<q~TyhTrHuY"
    "t*49v<uf41tyOqEoQLU-8tD{eWS!ZA^QSIPMcLJpDdF$%+U#10iV~m)97_t~L^}b-"
    "x8Y4CjHtiK^K0voB0B)OhIo<{GRyjRE*BEzD$_Wo90hqIhI3+ZjKi@d+FXjg}ar37Gy^Coo;LM*4c?+u0Sk77xJuG!9V(|CW"
    "*th^N>d1c9do5WorI3&dOf6)^QW0AGQ>U!^4yOplJqV4eaUy9(3$Z4R8Z3X0F5#o4M^gH;8@xB{sOLIG(_sHg@2`4RNgZ7WD"
    "Zq-8Z7jfP8B69#No|6GvixF&^aEFYY^2luW3R|}ER-"
    "8?N12p2{0rFH_DfNRGsQd~&11jj;1=@@IYFF?{pc`Ph4YXOE08_=}z4lR%K*9?^dj1*%5^QW)OpEmWiNvLrgxCXNT49Yk>MW"
    "o6E8Gtz01i<uLV%Y{~EFZn4!aP{!U}bk2{D2RhpQ6dCJ~0jP05T!l&TYYl6v<CR2c!^`5YG{QMRVdl1qJv3^zs%B_@g&(5w@"
    "cx3s?jl)}+5lj`Kc{T!XC4TT9fT0kxDxOUX0FcvY3>S=o!g00c%%V1HJbg7ON0H+vx5de`93T+F(wc=?8+Te!6t<c0C}e^{1"
    "DE;Br4Jva}pB}KOtym|EA;I}AZSK<vQo}w}>>j;mow(`!L-"
    "kA$FOIaxzkaoFYDD!wCT_N60TILxkVRR;X@6B244hGKHWcfiD06QJs|A@9K;BbXiW}w+Od`3O^<}(IC6C^9LJ(;TDs7i1L*7"
    "27Dh5XuRfTf5Y$5o{7ouQ{Suwr5<hCS3PSyOwUg~>5OVx=ZIfZcTU1g0oUyT1jG!3}AD=3aE!kTE}_&T0B=M$>1LMhMAxD~)"
    ";g8B$Z*rbbfg)_w<oR#qmWvoJ7}8xWrmN2~3Uy+KyOmK{)D7Cg@^m4R90Vl?Zou7Jr4U`_<Dc4y2z?hHN;Hc*)oQ`eCv<s5c"
    "@4`rc^jdVqkvLy(EvIm=~@+i;rAC~s=EU+Qg{|!>s6SOG#Cq;%#$C_lnmwL5{Yiaszk*V>VOief?j6{Rz1QN6q>2-"
    "kYEG9K`AKj8kYLM+&JSs_r)TOCP5)=xDk|_yRw(yT8$w+h8Ky4RLoE)X+Uh3!pw87dcaxgTS6k;k`LnQ*Puc1unQlPbm>#0l"
    "w8RS5PD=?$Ah_`|a&_>z>#Bf1BVEn*%h2%Qge+FnZ=~+m6=uo!<4IPpr6s=I8eK%p&bn+Tqaun*nFIai}KH2(QxavrUip8)_"
    "Y<SvQ2c;M|1`8KeaNZ;%Nv;iQw3r$Vrfv>gp)}b9CCkQ!AZ^G;;BnHl4H;+_7%pCs&0u^^!E^%w+LoPqn0k~QEJebbEznzJ?"
    "vaSbbBV|@@RmX#zzyJ|mCE(w_zg|lo>FFpR$!`R2fJ|_PP?(vm(fL}c8+o1lgXjPGiqrdjV?=YjDY<P%4(l^o4RDiX^{91#!"
    "Q`&a7153UL4!Qz!v`4ANB3AYlk8XJtr7|dpHc^K|dNf!;xbL!?6pVgln4LZ3-"
    "B!=ld87?GH!3KN^nuo)i1RjmEYc50fAWh3f|Wco1TY)EkHW&<+we>I-k=hy8J6n%^s`jgdEwW8WW+6R$rC2YzUW_SlY-fju6"
    "1K_WbRG#CqCjNzZyac$w+{x}*&A{p5OF%EW@+T}h*;w3oNlp5LbW`Ke)CTp@8-"
    "8Cm*cVAtbRa#}DN7gh2&cJ!C8OC_dDN+xBPunrs_H9cwQ%kj;h$*NlB^Fw-JCA}4qnKu-Ox_?yZ@*;2*aM-e9V=-"
    "VsR%~fHvXpNN6C{rngY#zHcm^*>`+{pEJ^VdLx6@1DCkTTr~r~EAU;JwcF#&iYca1%o-lG6%|p*h(+W-"
    "=00UH(J^bIhsL0FmPI5j%!Lo8gMicq!e|hGZ{H0_5r7^{x-"
    "zDRG3jvKuz6Tcu<DzzPDVVC*vlLm<1^Ec*nBm}`GqL{pcCk3WJDs1;Zhk=>{)=H9ncwl?@E2qMd@4K#4|(p(vo#-"
    "sMO$KII2b!4&l%Y6a43Z6NBz)uZO@M!Z<xeU9~i42jsiCb0}p-"
    "}dR{+r9gr_Ba33(?x5Y>sm&RZ)h+WrB`r`!t^u}Xn90^x=L)&+3$BD*nAe>;745HYJ?U6eg4-"
    "zMGg`bE)7$(WL7ku#?Rf1KyZPIhsd{W0TK!1XFNZN&M^M_p~D+IX)29iYMN2HFP66NJXutD`wVBti!p@m_&6u9Owpvnvx{V<"
    "j{)5X>7&guTW%-74F{OIyW6P-~s<#Kb6Z_arpjMKrcSuzY@!Dj4|6=TKOnfEAgB0&KN#z-"
    "BML^~CYf;vvCCP!4QHssgT;Yyx2fq4z(B2i|iYu=D+k4YDlSLXbrQ`^8Q_A4X3>Z6ME8Y<FD2h!X|UZ4}A7e(n9AygD0X+J9"
    "KISf?y6!K6$oJ9cE7)er*Q8?$l-"
    "FxpS)W|SF3x_Rlj{Qv)uSGMEaw!y?0li}ZdccSv!M8X3O|c|QPwOzdrP11H1=Uen!VYM}y#Q>2s0~w&LLio!KvKR$fMF*?f)"
    "s(L$1FTQAl;k3nQtpVnjqP=3Nln*?IWkCI|GG~)W^L_%T-"
    "WC4+k8KXrTu)F9j71+!y(FL+O(?%6PkVupbT&I7jWJCI^aDQBDfOu)!K@hyV-"
    "@u5<1SR*pHWrb9YxdeLrM2=OFB0y7EHZ1?xSmKYDMF(q+x03?s+hSbB+y$&#X%qP=~JCK*L1r_~No8Jf$966a7ZCHRUb%38D"
    "$aTVCCtE;K=^dL^(-8u(LrNS>+RLMoQZX{pLD)Vcr}3#oBoOp;DIX+ArmX~c*fsCba}U5+e-"
    "T!h5Taw}KvYu{{I%5B<s2cLC>9k+OoI!#tthGr7;hXggDO)V<wLsBp-?&d4%E5Ad=mhT1WFfC-W=$F^O_iEkpxE(a-"
    "8~wEu!3&hm4`TI!7fJ1XgHm`9L3kV?r76wXSFX>%;tdc4Emnb~8na>~O&XB~gm=nO_Q20I=M4-"
    "K4*I69ix?D8Y%V!*`Sv0zQU?QAEoV%9HQO%rOOW;!F`$TNq$?2ZmuvInS~b5A6-"
    "JB7G+LBr{g`LMC{xXQ#94+2wS0H(i{c&u`|7%exPkHy^I97T344lO>3!4(yP$8|;k$E=dBW>#fi!C1y#MaoXu+GFOgcn(VTV"
    ")G8SH1B#B*gf>E=rDSC_KcNIXpu~D<Y#}g`fN0TURCHQp4WAvTE@Lc%6%Np`hE{^7PAk?)gDyEMSZE16*~@^B0GM8_M`2055"
    "bO!;KbgJ=U~_2FC~gD&Hp$We-4{t-n>;Nkt-mA8i0kMSiGn+<sCZ03EKsZZ2K!ZC(nwHk2PRsiQ%xl#s0KSG)sJ)l6@}<cuI"
    "8+DVLd}dYeE6Xf|XR{NL2K#tOOy4Va*8xecT{EfF|+jCax{iIA1w)SngUN2Zm16HgiVg^YP)COXA;aMdN4U>yjcK(%@@pRYS"
    "|F9`2D#WTZL4!YYn+2}VZMv*b6D;OEC0E`!ABY<K-PCKme?5jq}2&w3DFpG!AGDV4Zs^i46h^~PLpi3Ne{Ul-sFAx3Q1f@nt"
    "cBxhWS0P9*}Sq!VP+lZT{j+Qe0nTV{x))u*-"
    "={XxGBnhBZj*c)E2QsSzlcADhH<Qs$D{$c2kem<tMsKri@~wgm*Bj`<hLCG2nFcwBQ=(zMMSm6}UYQcIGAz}go0i%;;8CS6A"
    "uhM*0|UtD(;7{3>tY?Fv~QYpO-dIl3ENAkgygYGdm3ZE@iZkw0r|Sh#QYg`wftyJ`2p#yZcvVZT$3sx6@@`R+y1C$`~EK-"
    "+7Ou7AWXo5*k<I`lY2|4YX(|ZzqN$i1E_=L%XD~XFQuume1WbGvD!zi@sc9`#wyZRR}^7>5Al<9W(P-"
    "Ww$}l57*M2#XEfc4gVYH~u<09_M3k|jl>;!$wgrLy$U<obOeQbST<hli*0SCHlI&T|4K|4d8Lh6w)!OK}Dthgh96qL3_TDw8"
    "ntaSA`LLO-XiG+{SWFwb#9oGeP{-<0FfOptykOPTU7OU(Nn`(=MQl-Pe-"
    "^4)`dOGua?z(Ck=Zd`B1s@D^YvrSP?c20(Xw1hN=^leMbK{-"
    "X3ZyNPC4uh18`54wuhEK*FIZqOWkTy>X)VRGgFKu%qxAV0xf}LyN;yAhnEcuDUB!zo;7%!Lugd!wr<fH!y(fvbwbe)Uoqx@m"
    "ZPd0=TgU|rC9%|b~ddV!sUTn+<+%P>x`2{C83N>nZc}m1d|s-"
    "zb{VjvC11!RluYaJ29F#WR;CPtnuEHsrOy7QS_pVGU0)AWxlVKE*dMEXNW>M^Z_o*xlDwE0w(LEnI1!m1+DvWNtqyy!eCqhI"
    "1L@n219hs<z(49uzeL<M%x+>(atV0suat)Ro=R`+Ezg<WJ!^p`m=Z<<}_l#b$uySUa!fmSr&HzT5pFx7k5Px`F7v^7v~pqmB"
    ";3}tjthWjxGpby%=HuWc?3O<cv*a_sdEaq+$@L*F3%CmmBqoX#s1Hm&Xbb#*2uMf^^Nh*1Ltl^Ce3~9SeZ(7L0#`pH@B*3qP"
    "J|*GoGvmlrP`hYVZsY#Cz`s0}lU_2^IE7;QF318CCY(&LZs7FV;&rM&pWGevn(pyi??S-"
    "j|TEEvnF)0?_WuC#fkhZ|yom)9p%gQ-gyjq+&?iz9vPN~Bsi05kk%UW4Z7H7k$I-"
    "!ya7$v}>({iX|lTUzBe<2TE)^nWm^Rz*WlMLly#Tea#0H&KsegC>DzKORkv=J?mg&cvLYT+DC5&Fk<9G?ZsY$3@~pw<G!a&^"
    "a*YjY0JzPW_142FZI3Bv*noKbrhNkOr@T)F+T8M<0JEmWHo^<Vld`M<0J6NTb(48W2bT&<{O0|22??5~Rrw#nPBSlH%oMo;z"
    "l0IyUE*A1CL)_83;F=eK)udiwwXpR*~u7m(h5I7asCaMX-"
    ";{KvxKybcF**RkTRKMoG}bvQf;hh(Wg4vzloaMXPC2cL`gIvk35j{j(UNZBh*2^Df}v&-V>g2`jixzMwlk7-"
    "~o>bnTU(Yu`7+sDY?1J>|Wuv`h&{OIDxf;D;-EM}&Qqs5QLmj5bPo&;-"
    "twD_@Ljb8;zvD)GXAEIx+3YOx$iyw?FpCvWf)Gx8&Cnl^<=5%oZ6JN|OZ|^SVHy4xJ=^5rN_X~!_u3-"
    "2cXxx{fsk!gdkAkNEGBnI|pA^&m2xz>Qq46X%lGlC&G=rC+safoYoz(DUXcT9C`f<2nd5tN!MmR@@Rup4RoujGC<TG_TQ@0L"
    "lq2v8(J`UhTK5q<=;hHua{x{%YmI5FEls^&<mdHB^QcL>i`n)7sE{@otXNWFL`153b`HsGWfA`}5z~nIvd*y}m{9VFvY=0l%"
    "u2yv_7V*yp-1$Dhr5(=rzW6g>-2Fbly(Zw&9{cA4-"
    "v2(p2U^enSxCkEKESnWAc^Il5BNR}#0hbWi$ZFN^6B@H_V3gYzYpx;x52LE$)`UJ*rRWQt!$!;KM}V5Z-"
    "ZSMPZxh0u*cs9yOtz>79w$M``cjG=GZ?M+r~AeNQZs29w~wkb_#C66zlCu;4LVsuA}QM&uU#u>~4m22MH%%Fh4>SHc7BbGir"
    "O(zM$GjDbOR>odhq6(#?fdZpmnt`cj(A;>)EQQB>O^l<Dy*r#p_=4TZ|0Wf2lxiH^5;0VfpI7lD^3u|xxH;hr}A_T<MA1M>r"
    "FTO|_@L6+<L16#VIhAAS-^wM-"
    "P2}b1zR0C009koHl)Ji*j1{+794Z5Gk^{4r^DpkS9ZiN_jyDBPqxnk5cCw2a?d39VC^T>W824CTC+yVe<<Li09nO8;rkcM>6"
    "N*6daGAc;a7Z#B9yYt2I<lNF`ur)ab!xsrR2mz$$g(6%XQdZb64~QeEsv-"
    "@yRKiMb1XVg&ZGw_zzZ+_mN5#N30H81@H`ej&ba4%ff4DuvwKGvsl|j3(x>+!$>KtY99TKuC-qt0$d@zK3@qEdv#r$S*saD&"
    "UJHte8D;HOnMymX6d!I?2<l}te?wS`L&Tr?|?DTXtB^-"
    "0X25q%bCi0wiRe7AOYFy=XZ9S01r=f_bw_3_6ZiXz7Rd*l=UO#D|f4maMDdhUNvGxOmhwPJ*XLzNC>jVr{s!+3h_vOQEP0y2"
    "#4~%^W!M~%(8cT8IaNXt07}Qhtb!#16BPMIKWN8<RGecfqZD)mHXA;DhZc5`qSmCk`R<iRCb)Z3>$4c_9IV}Qg*o67f;A<~k"
    "Av;sqH<g=Xbr>)~hpOlclz{7CQ$FO4M=%2l2ZwjFunHAmr5ZvBuO>vbA`L`&F>Q*3MpfULQ#Zy!tiCbbv7t}5hwZ+aM-"
    "9LC2L@JZ_w-e-Ub_hmJp}5*czz|F7@LdW-r&tlgNn~ART0}PLW6Z&-"
    "`I0`9RT!<LM4J_XCXBM9uGX>`CPe2T?Xp{R_tjc5v2-"
    "T^+c4@)(t9DTQL^2zAB)_y4xr%qHPv5N`K^i8ZP~r)tygoMfAX>%QN+;y07{3?d<9oq^@wAW|gd;2~4R4h#;|gr`azQr|jr^"
    "$yj`%FA2-"
    "uYt#%(UTEL*l%cwWnbajr$R1(Mq8}=wL4}INNnd;1$gI`NRo^L1O9Q1*k_D9+rv(w4EKE>EWn5U=#})+lgfT>4`LxQ?_2-"
    "Ukv}551zRA=e%K6RBhuNJw9^GBfZf@y@QRBPg#mTST3LfLuuv7To#pNAZMQ9S$BliBR2cKL|PH*q7t{VgNSNb8{bGFMZ0vlg"
    "odA30p;Xcl;F&uP5BluR-6-"
    "dwX`Ma~*JEse5@a$WczEwpf1RP9!BcFc$JwJc(;g&XYb9eRY?HO#!+5h$K(|?<MoZL*W=U2DSMl^onQK$3E$@$$o+~LkgLeZ"
    "IX=GLn}`^s&6)mnA$*UhK*?Cq5w_m6yG#TRy4KX5&J2Sh+2J!k*d^6BOcIHP(0&6qAuX8#*TOc$5aIVd1p53loHO{VWB?`C&"
    "5)3e#dgel}~;tqy4A1;_+_`2is=X5QQy26Tm7Q*}ybO85Uv1EHSl+37aRFSknMk{FA_Cm|LUkHwWcliMu)M0BK)QtL)5?f0+"
    "AFybSMWS?Z{Y#41N}q^R`9~B2>zr<MS};S`JO)vwI&jG3PN91FkU79jf3UezEVrXOp&G4jLp^=Hpa=Q|)ev@^v6NJcdnibxQ"
    "0Ym5(!;yj^ap6$$21bX5?lpQ^-kxf3;3~ou+-"
    "f!(#$C6>I)fsD=VYEAB>f9yD}|oIBHB~KPANPp1X|=v1M5(&SN;3jR}8aLHt{o?Fc^9wM^<8*>jYe>CoL_^?#O?5~d2QRpj5"
    "{yL~N;nvd*Eu_<2pQTZ8`Q_ruzbN7$Yg{+M+`nwm#;H`tNbgyq6fiuX8OpoSjOAEAz`4&7z3)@FM;m0GuBvH_lM5WZQ=37)Z"
    "{DiK|=O#}m#AQP#x~^9?8Uy#Z#+ok3vzdy@j4#eMv1+KsP|qhLn+}~}aM|#pDDxyQ{o(q&Bh@Tf<m(>a>oD-aCF|PwE~pM!-"
    "{POk4mSp)EBiYgiSeFZvjG;8E|vWo^fYz0kd2vMRdCDQ#wpZk<67>^&}EoQ>ce-"
    "4o(q7rjL}Fq#7qf(qHdw_VFDgHerBf(#xO>g+?}MJ>H$o`F3|VkTTSmr%Z|a{gO_qx1?A@+=y2*Q@!5KCtY&M8#-"
    "p3Oix|2?S#$WT6EgO3#NHV=CE9Tk5cTEjgZT~x8G6X|JP3d$fy+CjmcW&vuUAsDKa!vFTy*CSs!;{MP^cclTF7!&+#r6$t03"
    "TD8En8|b22*a2)I)=qix;su0?)G6~8^)3f~%{D`D6r>zUcHB!^DXPl8vifCg)cxuY(~eIj*%W*n=FkD{P}h}1esS^%MyRg6`"
    "t)DuB^t?b%7%BN+sxrPwDPph}LljEbeK?vU97Aw_}-}yUiB}TkWgLw^{{K()Q3jLRd$_HK;z6MG2@>u-"
    "!g@K6Dmj~jnFAUUb;^ol|O|o|il3~{Z24X+C#uY)4k`@NVbU^c!JvqE&{wFm?I-4S1I&8!-"
    "DRn`dB5D+9*oNx6$<>^$yP|%Dvk>dY6#T_i>+%t}AWQgRX*6CXzzy3m^dWC3(2dDGjU}!ow`YfMiKgl#C{Q8Y8kBwl)(}f-"
    "B2q0F1##ou1?7=(KDm5%IPHG8J+*w}e0n!IKi3~`|Ml?0?bJA1T+9yNVxI(QR*(uYu@PbIlpGni7gs0q>u)}Y@uw0LT8+=1Q"
    "gBBG8=fbN%iB-a^V`|+ueUR_`3@c9-TW4W@8#+I-"
    "QDHl=GU9s*+u(X4yYXVz%Bt*lx6hW<pQk5tMkcpcDFeG+iZG!1B2SlUmn3}mL3>bOXY!CZbU@dDg!28GDL`Pl!yFjadkVtnE"
    "&exCFv!AcZXkqjF24|)-"
    "WxF`j!a7|KwV4pj@hWKgVt{qKEA(@Cxr^kY+&$TDy8OD2Sk<iXc!P=wbkc!e~ai6Tb>EEXr+NyGYlvNwX9Y1c7c}3W}1WZgi"
    "gJ-)<I{=j=VoRX&TS(pbu|^BA`n6!(w#uR5OVJR>Cq=&AUHA^3?!)`u$b<tI@T^r>s`3{=*S-"
    "A;?($<&?jR6&0EAhPTLBqU!gTY^14eZTks9>s6^Pj`7>;7weuulY)sGDakc)osa2ffuAR>?(<d1a2EIJao+u>(6U=xTDP9Mm"
    "Nr$x)njP8V>+Z=w3I70-"
    "i3bwA#uB1C1z^p|AN^94<!x8{<iAvda6ajO7M`0ZL$1c|ojo?^j*b8!Krq!{T%sgq?h84`JU>*$J|Ziw$V%EWLlI8l6p%8=H"
    "bdImZU&M#19*2016&#`tiF8H^j?D7$Z5f4IDB_?-"
    "3U+Pka2+w~mx{jzUd?fV(;W|y;T1ZTRqzWQ)egC{=|8~>_45!cDTr`L;{n>&~jm~v+Dm-"
    "V{MeSVzJKHXiw&~xKtetLSR);v*DA-"
    "~cuM1&2uyf%cj&qe7J*}Mfieg$9nEIRw!pwgwOYuz=K%w&T|8d$$0?V28H!j4k=aLgHYhAQ9>z7AOvyQC2rXzOr#LlPn|0(M"
    "c6O|5z_Hrk~-cVBXgyY?x5XSy-"
    "&DQI;KyCNY%{jlVnJrxEdBWsN|)<L6zfJ~mqtJ0DMjEARtkX!V!oEMz<rM$y!$?#XD<9g&qsvcVWf{pqG3Unyc(New<Kq7${"
    "h@X{R`PJ?9kbC*cjuKsSqB>Kpz>qYQF=tM>YrlETDH0V^L`0ys!tWMn=Z$b$zWml<VC0FgN#AhJxLNKO383zzD-"
    "C}%d4tNFUSILGTfXmS1lu@O9h9Yq)oA3$IBHzd2mBW~$O};YAUqYJvQtL!)^XQ7=655Q&)<z;7@tz?9nnaksJBeC-"
    "!%nXz#VT^!Dnn6-"
    "n(wlg36YGV67g&!p5O^6tWAte3cE`y0Jh%mRn2won;|)v8iu>m(APX+~YuS#}n?`rUUE^)yY@9WqXaiS3tRch3uJ2-"
    "D*J6WAE-4(wwLVWD4Z+S4(D-t&`c+l6uU<0&i)B(k86msiAeU%tpwULg4B<-"
    "N<F<PHZrPjY{fv;`JQ6&B!@1Gw8B0+H8t0dp$P{&_v%lSJ&OO&4B4vgBv9R&c*s3GklF!3+gf^;~wKuy2Bn=ygh95(4!ZFs2"
    "rz!KaY)qWKWxM*({N`A<wc9Sd4}23oi$1zeNamqka>R{<eDB2v)c-"
    "cxm8n>(_CyQ!4#F^z*eJ88qy!8c>zPOmcqJ3SZ4_zM4rUy_E^xd`*~@&^rORjWoNlYCfd+(r9&Sm))5=jqJ$t_T3%n@9ufAQ"
    "OC$PXnY`bHr|;;$HfgWfHn%e`nPmEr|%7YZz!GgDzAXT*+eWc!B5^#D7f{t>Wsi5N~tsI8Vc^L)BEW5KGyj@f6y6?J&J`i-"
    "W=5IM2@a}F7x)(C4s~`7+Rc-"
    "Y4=l)MEa;$Nhw$vTj5TON|Nr=xklqb*}X%CP#RGyo>FxIJCFyma|lE%2Rd@KL{xSu3UyfHx+A|&<HH)m&x2UT3&AS2w4_5xD"
    "hI9Z<<$4JhgAklRtE+Lv>JgdigWc;I7_#r2fhKBU16(RZTxo7W3193>+l^{i?wQplbiB2F%)iNUnmK}LSAo{n9#u)LJQEAJP"
    "wI@`I0>u>ygR?l%&$R+#aS@iPA6Eff1uVCxX5s!#3zl<XT;}2-"
    "M>2CI;(eAhCvykfl1^g91V?p$;q&HI=$~x|VwU9;8>>;j^XP>TpXoj8y6JdNp?wR4-"
    "vbENQM{bjdEru;t2XqDD1&OY4wAJ25FUg)*w3@e@7dDOW2rTJG<7G%e;<U`z})sAN$lz2FTMOF$(@yUp!sr?GzB5JK88dS%;"
    "xJiZcqbHsJYGL(-"
    "Gec0CPG3xiuaW4ni)w*GFtmRv=>NBbxFQdLsU%#mYm6)<#RE$OcN|J`$skX&zv@PZi^*AOsv5{ZL2A<l=X?@Skj25A~t=*&#"
    "rkF;~SJ|#)`l__KHut;c)i>Ti)tIV&3zd8=m3-%ztXSfHQ6va;2HVi5_*|o6S;H|iCcg$tscQ9-"
    "vc^jZV_E8>4u~`6J#4s*?~apvZ!}0(z9>u2nR4Dtvt^@QCfIHzw)ewOFCCa6ON4Z}PmN#wKC)ijgFMBaJ1tsM0z@|JF_=8#g"
    "C^l?oe}IObxp;pgZZ9Dz=}@UXou55>o=)8LSWb&y+DHq4rs|D|4O%2YIX)zuwh9^r|xn_ZRY7wDvKkp!$2tUwUD$l0*aImPC"
    "_H-^t?NI86*N<OjlRl7>&vsu<iMcTPO_lTRKEhVA;)1pX|x>qh)(sJ%n)?-Aj@ht?S-{Y27ay(<2Aw{yyygAH5f9hy"
)


def _v4_fixture() -> bytes:
    return decompress(b85decode(_V4_FIXTURE_B85))


def _replace_once(source: bytes, before: bytes, after: bytes) -> bytes:
    if source.count(before) != 1:
        raise AssertionError(f"fixture replacement is not unique: {before!r}")
    return source.replace(before, after, 1)


def _boundary_expected(code: str) -> tuple[bool, str, int]:
    if code == "ACCEPTED":
        return True, "GUARD_ACCEPTED", 1
    if code == "SIGNATURE_INVALID":
        return False, "GUARD_ACCEPTED", 1
    return False, code, 0


def _runtime_witnesses():
    return tuple(witness for witness in required_witnesses() if witness.runtime)


class H1BoundaryTests(unittest.TestCase):
    def test_literal_relation_is_closed(self) -> None:
        validate_relation()

    def test_python_matches_all_frozen_o14_boundary_vectors(self) -> None:
        witnesses = _runtime_witnesses()
        self.assertEqual(len(witnesses), 29)
        for witness in witnesses:
            with self.subTest(witness=witness.identifier):
                event = witness.event
                key = event.binding.verification_key if event.binding else b""
                observed = ed25519_verify_detailed(
                    key, event.signature, event.transcript
                )
                accepted, guard, equations = _boundary_expected(
                    witness.expected_code
                )
                self.assertEqual(
                    observed,
                    {
                        "accepted": accepted,
                        "equationInvocations": equations,
                        "guardCode": guard,
                    },
                )

    def test_javascript_independently_matches_python_boundary(self) -> None:
        records = []
        expected = []
        for witness in _runtime_witnesses():
            event = witness.event
            key = event.binding.verification_key if event.binding else b""
            records.append(
                {
                    "id": witness.identifier,
                    "messageHex": event.transcript.hex(),
                    "publicKeyHex": key.hex(),
                    "signatureHex": event.signature.hex(),
                }
            )
            expected.append(
                {
                    "id": witness.identifier,
                    **ed25519_verify_detailed(
                        key, event.signature, event.transcript
                    ),
                }
            )
        with tempfile.TemporaryDirectory(prefix="styx-c03-h1-") as tmp:
            input_path = Path(tmp) / "input.json"
            output_path = Path(tmp) / "output.json"
            input_path.write_bytes(
                dumps(
                    {
                        "records": records,
                        "schema": "styx-c03-h1-boundary-input/v1",
                    }
                )
            )
            completed = subprocess.run(
                [
                    "node",
                    str(ROOT / "node_adapter.mjs"),
                    "--h1-input",
                    str(input_path),
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            observed = loads(output_path.read_bytes())
            self.assertEqual(observed["observations"], expected)


class H2AdmissionOrderTests(unittest.TestCase):
    def setUp(self) -> None:
        hostiles = load(CORPUS / "adversarial-mutations.json")[
            "kAdmissionScenarios"
        ]
        self.pending = deepcopy(
            next(
                row
                for row in hostiles
                if row["id"]
                == "k-hostile-required-opening-and-pending-ancestor"
            )
        )

    @staticmethod
    def _resign(record: dict, seed_label: str) -> dict:
        value = deepcopy(record)
        transcript = bytes.fromhex(value["transcriptHex"])
        public, signature = ed25519_sign(
            synthetic_octets(seed_label, 32), transcript
        )
        value["binding"]["verificationKeyHex"] = public.hex()
        value["signatureHex"] = signature.hex()
        return value

    def _root_event(self, identifier: str, *, parents=()) -> dict:
        genesis = self.pending["acceptedGenesisRecord"]
        predecessor = self.pending["records"][0]["eventReferenceHex"]
        return _application_vector(
            identifier,
            _event_fields(
                identifier,
                sequence=1 if parents else 0,
                predecessor=predecessor if parents else None,
                parents=list(parents),
                credential=bytes.fromhex(genesis["genesisReferenceHex"]),
                context=bytes.fromhex(
                    genesis["fields"]["contextIdentifierHex"]
                ),
                genesis_reference=bytes.fromhex(
                    genesis["genesisReferenceHex"]
                ),
            ),
            "k-linear/root",
        )

    def test_pending_dependency_does_not_hide_invalid_signature(self) -> None:
        genesis = self.pending["acceptedGenesisRecord"]
        pending, descendant = deepcopy(self.pending["records"])
        signature = bytearray.fromhex(descendant["signatureHex"])
        signature[-1] ^= 1
        descendant["signatureHex"] = bytes(signature).hex()
        observed = {
            row["id"]: row
            for row in evaluate_k_admission_graph(
                genesis, [pending, descendant]
            )
        }
        self.assertEqual(
            observed[pending["id"]]["protocolErrorCode"], "PENDING_OPENING"
        )
        self.assertEqual(
            (
                observed[descendant["id"]]["protocolErrorCode"],
                observed[descendant["id"]]["stage"],
            ),
            ("INVALID", "S3_KERNEL_STRUCTURAL"),
        )

    def test_pending_and_ready_siblings_form_one_complete_fork(self) -> None:
        genesis = self.pending["acceptedGenesisRecord"]
        pending = deepcopy(self.pending["records"][0])
        sibling = self._root_event("package-a-ready-sibling")
        observations = evaluate_k_admission_graph(genesis, [pending, sibling])
        self.assertEqual(
            {
                (row["kBindingAdmission"], row["protocolErrorCode"], row["stage"])
                for row in observations
            },
            {("ADMITTED", "FORK_EVIDENCE", "EVENT_LOCAL")},
        )

    def test_pending_plus_absent_dependency_fails_at_s4(self) -> None:
        genesis = self.pending["acceptedGenesisRecord"]
        pending = deepcopy(self.pending["records"][0])
        descendant = self._root_event(
            "package-a-pending-plus-absent",
            parents=("ab" * 32,),
        )
        observed = {
            row["id"]: row
            for row in evaluate_k_admission_graph(
                genesis, [pending, descendant]
            )
        }
        self.assertEqual(
            (
                observed[descendant["id"]]["kBindingAdmission"],
                observed[descendant["id"]]["protocolErrorCode"],
                observed[descendant["id"]]["stage"],
            ),
            ("REJECTED", "DEPENDENCY_DEFERRED", "S4_GRAPH_ADMISSION"),
        )

    def test_graph_results_match_javascript_for_hostile_rows(self) -> None:
        genesis = self.pending["acceptedGenesisRecord"]
        pending, descendant = deepcopy(self.pending["records"])
        signature = bytearray.fromhex(descendant["signatureHex"])
        signature[-1] ^= 1
        descendant["signatureHex"] = bytes(signature).hex()
        sibling = self._root_event("package-a-ready-sibling-js")
        scenarios = [
            {
                "acceptedGenesisRecord": genesis,
                "graphEvaluation": True,
                "id": "pending-invalid",
                "records": [pending, descendant],
            },
            {
                "acceptedGenesisRecord": genesis,
                "graphEvaluation": True,
                "id": "pending-fork",
                "records": [pending, sibling],
            },
        ]
        expected = [
            {
                "id": scenario["id"],
                "observations": evaluate_k_admission_graph(
                    genesis, scenario["records"]
                ),
            }
            for scenario in scenarios
        ]
        with tempfile.TemporaryDirectory(prefix="styx-c03-h2-") as tmp:
            input_path = Path(tmp) / "input.json"
            output_path = Path(tmp) / "output.json"
            input_path.write_bytes(dumps({"scenarios": scenarios}))
            completed = subprocess.run(
                [
                    "node",
                    str(ROOT / "node_adapter.mjs"),
                    "--k-scenario-input",
                    str(input_path),
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                loads(output_path.read_bytes()),
                {"observations": expected, "result": "PASS"},
            )

    def test_literal_slot_relation_exercises_both_lexical_schedules(self) -> None:
        schedules = {
            case["lexicalSchedule"]
            for case in slot_cases()
            if case["lexicalSchedule"] != "NOT_APPLICABLE"
        }
        self.assertEqual(schedules, {"LEFT_LT_RIGHT", "LEFT_GT_RIGHT"})

    def test_complete_relation_is_byte_equivalent_across_runtimes(self) -> None:
        self.assertEqual(run_runtime("python"), run_runtime("javascript"))

    def test_valid_aliases_authenticate_independently_and_commit_once(self) -> None:
        case = slot_cases()[62]
        rows = evaluate_k_admission_graph(
            case["genesis"], case["records"], presentation_evidence=True
        )
        targets = [row for row in rows if row["id"] in case["targets"]]
        aliases = [row for row in targets if row["id"].endswith(("-V", "-A"))]
        self.assertEqual(len(aliases), 2)
        self.assertEqual(
            {
                (
                    row["kBindingAdmission"],
                    row["coalescedPresentationCount"],
                    row["logicalEventEffectCount"],
                )
                for row in aliases
            },
            {("ADMITTED", 2, 1)},
        )
        self.assertEqual(
            {row["eventReferenceHex"] for row in aliases},
            {aliases[0]["logicalEventReferenceHex"]},
        )

    def test_invalid_alias_and_opening_cannot_poison_or_supply(self) -> None:
        for index, rejected_code, surviving_code in (
            (68, "INVALID", None),
            (80, "COMMITMENT_MISMATCH", None),
            (88, "INVALID", "PENDING_OPENING"),
            (94, "COMMITMENT_MISMATCH", "PENDING_OPENING"),
        ):
            with self.subTest(row=index + 1):
                case = slot_cases()[index]
                rows = evaluate_k_admission_graph(
                    case["genesis"],
                    case["records"],
                    presentation_evidence=True,
                )
                targets = [row for row in rows if row["id"] in case["targets"]]
                rejected = next(
                    row for row in targets if row["protocolErrorCode"] == rejected_code
                )
                self.assertEqual(
                    (
                        rejected["kBindingAdmission"],
                        rejected["coalescedPresentationCount"],
                        rejected["logicalEventEffectCount"],
                    ),
                    ("REJECTED", 0, 0),
                )
                survivor = next(
                    row
                    for row in targets
                    if row["eventReferenceHex"] == rejected["eventReferenceHex"]
                    and row["id"] != rejected["id"]
                )
                self.assertEqual(survivor["protocolErrorCode"], surviving_code)
                self.assertEqual(survivor["logicalEventEffectCount"], 1)

    def test_conflicting_stable_identifier_fails_before_graph_processing(self) -> None:
        case = slot_cases()[62]
        first = deepcopy(case["records"][-3])
        conflicting = deepcopy(case["records"][-2])
        conflicting["id"] = first["id"]
        with self.assertRaisesRegex(ProtocolError, "STRUCTURAL_REJECTION"):
            evaluate_k_admission_graph(case["genesis"], [first, conflicting])

    def test_relation_wrapper_identity_guard_is_bidirectional_and_local(self) -> None:
        case = slot_cases()[62]
        first = deepcopy(case["records"][-3])
        second = deepcopy(case["records"][-2])

        _validate_candidate_set_wrapper_identities(
            case["genesis"], case["records"]
        )
        _validate_candidate_set_wrapper_identities(
            case["genesis"], [first, deepcopy(first)]
        )

        different_wrapper_same_id = deepcopy(second)
        different_wrapper_same_id["id"] = first["id"]
        with self.assertRaisesRegex(
            RelationError, "stable ID names different wrapper bytes"
        ):
            _validate_candidate_set_wrapper_identities(
                case["genesis"], [first, different_wrapper_same_id]
            )

        identical_wrapper_different_id = deepcopy(first)
        identical_wrapper_different_id["id"] = f"{first['id']}-clone"
        with self.assertRaisesRegex(
            RelationError, "byte-identical wrappers use different stable IDs"
        ):
            _validate_candidate_set_wrapper_identities(
                case["genesis"], [first, identical_wrapper_different_id]
            )

    def test_private_collision_rows_do_not_claim_admission_or_effect(self) -> None:
        for case in slot_cases()[86:88]:
            with self.subTest(row=case["row"].row_id):
                from h1_h2_relation import _project_slot_case

                projected = _project_slot_case(case)
                self.assertEqual(
                    {row["classification"] for row in projected["observations"]},
                    {"REFERENCE_COLLISION_UNSUPPORTED", "UNIQUE"},
                )
                self.assertTrue(
                    all(
                        "logicalEventEffectCount" not in row
                        and "kBindingAdmission" not in row
                        for row in projected["observations"]
                    )
                )


class FinalGateGitIdentityTests(unittest.TestCase):
    def test_replace_ref_cannot_make_an_old_tree_look_clean(self) -> None:
        with tempfile.TemporaryDirectory(prefix="styx-c03-replace-ref-") as tmp:
            repo = Path(tmp) / "repo"
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(
                ["git", "-C", str(repo), "config", "user.name", "Styx test"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(repo), "config", "user.email", "test@invalid"],
                check=True,
            )
            tracked = repo / "tracked.txt"
            tracked.write_text("base\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
            subprocess.run(
                ["git", "-C", str(repo), "commit", "-qm", "base"], check=True
            )
            base = subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
            ).strip()
            tracked.write_text("candidate\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "commit", "-qam", "candidate"], check=True)
            candidate = subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
            ).strip()
            attacker_environment = dict(os.environ)
            attacker_environment.pop("GIT_NO_REPLACE_OBJECTS", None)
            subprocess.run(
                ["git", "-C", str(repo), "replace", candidate, base],
                check=True,
                env=attacker_environment,
            )
            subprocess.run(
                ["git", "-C", str(repo), "reset", "--hard", "-q", candidate],
                check=True,
                env=attacker_environment,
            )
            self.assertEqual(
                subprocess.check_output(
                    [
                        "git",
                        "-C",
                        str(repo),
                        "status",
                        "--porcelain=v1",
                        "--untracked-files=all",
                        "--ignored=matching",
                    ],
                    env=attacker_environment,
                    text=True,
                ),
                "",
            )
            with self.assertRaisesRegex(
                RelationError, "tracked checkout bytes mismatch"
            ):
                _clean_checkout(repo, candidate)

    def test_assume_unchanged_cannot_hide_modified_source_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="styx-c03-assume-unchanged-") as tmp:
            repo = Path(tmp) / "repo"
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            for key, value in (
                ("user.name", "Styx test"),
                ("user.email", "test@invalid"),
            ):
                subprocess.run(
                    ["git", "-C", str(repo), "config", key, value], check=True
                )
            tracked = repo / "tracked.txt"
            tracked.write_text("expected\n", encoding="utf-8")
            subprocess.run(
                ["git", "-C", str(repo), "add", "tracked.txt"], check=True
            )
            subprocess.run(
                ["git", "-C", str(repo), "commit", "-qm", "candidate"],
                check=True,
            )
            candidate = subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
            ).strip()
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "update-index",
                    "--assume-unchanged",
                    "tracked.txt",
                ],
                check=True,
            )
            tracked.write_text("malicious\n", encoding="utf-8")
            self.assertEqual(
                subprocess.check_output(
                    ["git", "-C", str(repo), "status", "--porcelain=v1"],
                    text=True,
                ),
                "",
            )
            with self.assertRaisesRegex(
                RelationError, "tracked checkout bytes mismatch"
            ):
                _clean_checkout(repo, candidate)

    def test_git_dir_environment_cannot_redirect_checkout_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="styx-c03-git-env-") as tmp:
            repo = Path(tmp) / "repo"
            other = Path(tmp) / "other"
            for path, content in ((repo, "expected\n"), (other, "other\n")):
                subprocess.run(["git", "init", "-q", str(path)], check=True)
                subprocess.run(
                    ["git", "-C", str(path), "config", "user.name", "Styx test"],
                    check=True,
                )
                subprocess.run(
                    ["git", "-C", str(path), "config", "user.email", "test@invalid"],
                    check=True,
                )
                (path / "tracked.txt").write_text(content, encoding="utf-8")
                subprocess.run(["git", "-C", str(path), "add", "tracked.txt"], check=True)
                subprocess.run(
                    ["git", "-C", str(path), "commit", "-qm", "initial"], check=True
                )
            candidate = subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
            ).strip()
            previous = os.environ.get("GIT_DIR")
            os.environ["GIT_DIR"] = str(other / ".git")
            try:
                _clean_checkout(repo, candidate)
            finally:
                if previous is None:
                    os.environ.pop("GIT_DIR", None)
                else:
                    os.environ["GIT_DIR"] = previous


class ProviderV4AuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = _v4_fixture()

    def test_exact_local_fixture_is_the_incorporated_provider_authority(self) -> None:
        self.assertEqual(sha256(self.fixture).hexdigest(), RATIFICATION_V4_SHA256)
        authority = _parse_v4_authority(self.fixture)
        self.assertEqual(
            (
                len(authority.slot_rows),
                len(authority.mutant_rows),
                len(authority.documentation_blocks),
                len(authority.tep_filenames),
                len(authority.command_ids),
            ),
            (38, 4, 3, 34, 18),
        )
        candidate = subprocess.check_output(
            ["git", "-C", str(REPO), "rev-parse", "HEAD"], text=True
        ).strip()
        _validate_v4_reconstruction(REPO, BASE_SHA, candidate, authority)

    def test_authority_identity_rejects_any_byte_change(self) -> None:
        changed = _replace_once(
            self.fixture,
            b"## 6. Literal additional relation rows",
            b"## 6. Literal additional relation rowz",
        )
        with self.assertRaisesRegex(RelationError, "identity mismatch"):
            _parse_v4_authority(changed)

    def test_v4_structure_rejects_section_relation_drift(self) -> None:
        mutations = (
            (
                b"## 6. Literal additional relation rows",
                b"## 60. Literal additional relation rows",
            ),
            (b"`H2-SLT-063` / `valid-signature-alias-01` | `V>A>I`",
             b"`H2-SLT-063` / `valid-signature-alias-01` | `A>V>I`"),
            (b"| `H2-SLT-063` / `valid-signature-alias-01` | `V>A>I` | V,A ADMITTED, same logical ref, coalesced=2, effect=1; I ADMITTED, coalesced=1, effect=1 |",
             b"| `H2-SLT-063` / `valid-signature-alias-01` | `V>A>I` | V,A ADMITTED, same logical ref, coalesced=3, effect=1; I ADMITTED, coalesced=1, effect=1 |"),
            (b"abort connected evaluation instead of attributing each multi-presentation outcome per record",
             b"abort all connected evaluation"),
            (b"`M-H2-GLOBAL-REFERENCE-ABORT` is killed by connected row 063, not solely by the\nprivate classifier.",
             b"`M-H2-GLOBAL-REFERENCE-ABORT` is killed by connected row 064, not solely by the\nprivate classifier."),
            (b"ISSUE_297_REST.json\nISSUE_297_BODY.txt",
             b"ISSUE_297_BODY.txt\nISSUE_297_REST.json"),
            (b"LANG=C.UTF-8\nLC_ALL=C.UTF-8\nTZ=UTC\nHOME=<gate-owned empty temp directory>",
             b"LANG=C.UTF-8\nLC_ALL=C.UTF-8\nTZ=Europe/Rome\nHOME=<gate-owned empty temp directory>"),
            (b"PREFLIGHT\nVALIDATE_RELATION",
             b"VALIDATE_RELATION\nPREFLIGHT"),
        )
        for before, after in mutations:
            with self.subTest(before=before):
                changed = _replace_once(self.fixture, before, after)
                with self.assertRaises(RelationError):
                    _parse_v4_structure(changed)

    def test_v4_reconstruction_rejects_document_or_guard_drift(self) -> None:
        candidate = subprocess.check_output(
            ["git", "-C", str(REPO), "rev-parse", "HEAD"], text=True
        ).strip()
        mutations = (
            (b"Package A repairs the isolated C0.3/K Ed25519 guard",
             b"Package A weakens the isolated C0.3/K Ed25519 guard"),
            (b'    "h1_h2_relation.py", "tests/test_h1_h2_relation.py",',
             b'    "tests/test_h1_h2_relation.py", "h1_h2_relation.py",'),
            (b"self.assertEqual(len(TOOL_FILES), 26)",
             b"self.assertEqual(len(TOOL_FILES), 27)"),
        )
        for before, after in mutations:
            with self.subTest(before=before):
                authority = _parse_v4_structure(
                    _replace_once(self.fixture, before, after)
                )
                with self.assertRaisesRegex(RelationError, "reconstruction mismatch"):
                    _validate_v4_reconstruction(
                        REPO, BASE_SHA, candidate, authority
                    )

    def test_code_local_mirror_drift_is_fail_closed(self) -> None:
        mirrors = (
            ("TEP_FILENAMES", tuple(reversed(relation.TEP_FILENAMES))),
            ("REQUIRED_COMMAND_IDS", tuple(reversed(relation.REQUIRED_COMMAND_IDS))),
            (
                "EXACT_RECONSTRUCTED_PINS",
                {**relation.EXACT_RECONSTRUCTED_PINS,
                 "tools/causal-flow-simulator/c03/README.md": "0" * 64},
            ),
            (
                "APPENDIX_MUTANT_DESCRIPTIONS",
                {**relation.APPENDIX_MUTANT_DESCRIPTIONS,
                 "M-H2-ALIAS-MULTI-EFFECT": "weakened"},
            ),
        )
        for name, replacement in mirrors:
            with self.subTest(name=name), mock.patch.object(
                relation, name, replacement
            ):
                with self.assertRaises(RelationError):
                    _parse_v4_structure(self.fixture)


class TechnicalEvidencePackageTests(unittest.TestCase):
    def test_closed_environment_contains_only_ratified_keys(self) -> None:
        tools, versions = _resolve_toolchain()
        self.assertEqual(len(versions.splitlines()), 5)
        with tempfile.TemporaryDirectory(prefix="styx-c03-env-test-") as tmp:
            environment = _closed_environment(tools, Path(tmp) / "environment")
            self.assertEqual(
                set(environment),
                {
                    "GIT_CONFIG_GLOBAL",
                    "GIT_CONFIG_NOSYSTEM",
                    "GIT_NO_REPLACE_OBJECTS",
                    "HOME",
                    "LANG",
                    "LC_ALL",
                    "PATH",
                    "PYTHONDONTWRITEBYTECODE",
                    "TMPDIR",
                    "TZ",
                },
            )
            self.assertNotIn("PYTHONPATH", environment)
            self.assertNotIn("PYTHONOPTIMIZE", environment)
            self.assertNotIn("NODE_OPTIONS", environment)

    def test_mutation_ledger_requires_exact_order_and_zero_exit(self) -> None:
        rows = [
            {
                "argv": ["python3", "detector.py", mutant],
                "checkoutRole": "CHECKOUT_1",
                "commandId": mutant,
                "exitStatus": 0,
                "stderrUtf8": "",
                "stdoutUtf8": "PASS\n",
            }
            for mutant in MUTANTS
        ]
        payload = b"".join(dumps(row) for row in rows)
        self.assertEqual(
            len(
                _validate_jsonl(
                    payload,
                    expected_ids=MUTANTS,
                    checkout_role="CHECKOUT_1",
                )
            ),
            24,
        )
        rows[-1]["exitStatus"] = 2
        with self.assertRaisesRegex(RelationError, "command-ledger row"):
            _validate_jsonl(
                b"".join(dumps(row) for row in rows),
                expected_ids=MUTANTS,
                checkout_role="CHECKOUT_1",
            )

    def test_flat_package_schema_and_manifest_are_exact(self) -> None:
        with tempfile.TemporaryDirectory(prefix="styx-c03-tep-test-") as tmp:
            package = Path(tmp) / "package"
            package.mkdir()
            for name in TEP_FILENAMES:
                if name not in {"PACKAGE_SCHEMA.txt", "SHA256SUMS.txt"}:
                    (package / name).write_bytes(f"fixture:{name}\n".encode())
            (package / "PACKAGE_SCHEMA.txt").write_bytes(
                "".join(f"{name}\n" for name in TEP_FILENAMES).encode("ascii")
            )
            (package / "SHA256SUMS.txt").write_bytes(_manifest_bytes(package))
            self.assertEqual(len(_verify_tep_structure(package)), 34)
            (package / "UNLISTED").write_text("no\n", encoding="utf-8")
            with self.assertRaisesRegex(RelationError, "artifact set"):
                _verify_tep_structure(package)

    def test_flat_package_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="styx-c03-tep-link-") as tmp:
            package = Path(tmp) / "package"
            package.mkdir()
            target = package / "target"
            target.write_text("target\n", encoding="utf-8")
            (package / "alias").symlink_to(target)
            with self.assertRaisesRegex(RelationError, "invalid package artifact"):
                _verify_tep_structure(package)


if __name__ == "__main__":
    unittest.main()
