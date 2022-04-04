# RiskIQ - PassiveTotal

RiskIQ PassiveTotal aggregates data from the whole internet, absorbing intelligence to identify threats and attacker infrastructure, and leverages machine learning to scale threat hunting and response. With PassiveTotal, you get context on who is attacking you, their tools and systems, and indicators of compromise outside the firewall—enterprise and third party. © [PassiveTotal](https://www.riskiq.com/products/passivetotal/)

## Lampyre script

In general this backend script provide ability to enrich IP/Domains (or whole netblock) with context through intelligence data from PassiveTotal.

List of features:

    1. Enriches domain with passive dns information (history of resolves).
    2. Enriches domain with history of whois records.
    3. Enriches domain with history of subdomains.
    4. Enriches every discovered IP with history of certificates, cookies, components which were discovered.
    5. Filters out noisy IP
    6. Filters out useless information by simple regexp.

![Settings](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAA8IAAAFNCAYAAADLktaJAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAEwSSURBVHhe7b17sBzFnefbcfel2d27o30/712F/7nyX+OIjWChY8YTcXd278jj8XjWj407i8ceCMq7O7NYYxsw4YdkG1swYE4LC4mnhIGxwYMRGGjJeG3x8h5jsA/PAfsABxAg89IDYQsP3pu3flmZ1VlZWX26z+lHZuvzUXzjVGXlo6q6S92fk9V9WocPH1arzaFDh9S3Htqj5v7H+UNlz0O3qYOHDgb7JIQQQgghhBBCxpGRiPBKJNhmz4O3BvskhBBCCCGEEELGkVWL8INPPxAU3GHyo6fuD/ZNCCGEEEIIIYSMOqsS4VcPvqouv+PioNwOk0vuvFj3FRqDEEIIIYQQQggZZVYlwgtP/TAottXcpp54/fvq2uC2Xu5/8r7gGIQQQgghhBBCyCizKhG+6Uc3BqXW5tqlg0ozgAh/4/6vB8cghBBCCCGEEEJGmVWJ8BV3XRqU2kq+/311cAARvnTfl4NjEEIIIYQQQggho8yqRHjrd+eCUlvJgCLc+c4FwTEIIYQQQgghhJBRZlUifNG3LwhKbSWIMCGEEEIIIYSQiLIqEb787u1Bqa1k0Fuj79wWHIMQQgghhBBCCBllViXCu3/4jaDUVjKgCN9w33XBMQghhBBCCCGEkFFmVSL8oyfvD0qtTfmt0YYnHg7Xk9z3xL3BMQghhBBCCCGEkFEmKML79u0bKN/d91315W9vDYrtMNl6+1ze13eCYxyvCT0uhBBCjs+EXifIYAmdT0IIIaRRhEPlofzoqR8G5XaY/PCp+4J9H6/hhZsQQuLOA0+8qO77SZEfLv40WGeU4XVhZeG8EUIIacqqRViy56HbgoI7SG5ZuDnY5/EcXrgJISTuXHvXM+ordzxd5tWDh4L1RhVeF1YWzhshhJCmjESEDx46qPY8eGtQdPtFJFjahvpcaT6486qhE+pnmuGFmxBC4k5IhA8eOqxefvVQmVC7lYbXhZWF80YIIaQpIxFhG7lN+pI7Lw5Kr5vt+7aN7XboQmzVwBlGhF15bkqo3bDhhZsQQuJOSIRvu/+5StmzPx3dL3p5XVhZOG+EEEKaMlIRlrx68FV1/5P3qW/c/3V16b4vq853LtCRvxMsfyJJvh361YOvBNuOIoWMhqXXzb1PPqp/DiOvUrcfiDAhhBwfCYnwN3+wv1K29MKrwbYrCa8LKwvnjRBCSFNGLsIryoNb1YYNW9WDoW1DZhARnrtjh3rL+W9R1/zghlWJcKvVMksFsj2UUF/9wgs3IYTEHUQ4jXDeCCGENGUkIrxu3bpaNmx9MFg3mAmK8E0P3K4l+Ne2vk0tPP3EUKIqdV1CIuyDCBNCSNp5JZdc+7lf+6VYsYvwhspr8unq5kCdiWaEr/PDhNdTQgghTRndjPBqXuTGIMIiufLTjdwO/da5t2oR7j58py5biQiLAPsREGFCCJmtvPDSwYrc3nTvfl0evQi7r6k3n67WTUFCK0GECSGERJaxivCDWzc4v5HeoLY+GCiXNm5becE2dWv1nL6bIuJ5149/pGX35Os+pF585Y28XKknXnhJ/folb9fl2+/ZqcskKxFhixVgCyJMCCGzlederIrwN+af1eVJifDhm9XpZlY4+LpsXoO3ni5ly9U7XZ2+oSg//eYH1dZy2Ywldfx2h3v1JPqOsVC95fZjwPcBbng9JYQQ0pTJzQiL4J5+s3nx692mdfPp+bJt624L1TPL/SLiKfK7Yec7Sxne/9IR9e6r36PXz7ztU3m93izxqEU4NEsc6qtfeOEmhJA4MgsirGUy9PpceV12ZLZvPSOtzi+t9bLuvyfcup19bfeXm+r5+6HXh38f4IbXU0IIIU0ZrwibF7Xqb3PlBVDWvRdBvyxUb4AU4qm0/FoZls8Dy8/3X/sH5QyxzWpE2Ce0HREmhJB0k6wI29ddifvaHHpdHvT1260XWvbb6JjXcL9+qJ5bR2dl7wPc8HpKCCGkKeMTYf1CZ2+LCmx3X+DMtpvlt9byW+eyjlevUh6OFWGJK8NyW7Ss2202w4rwcvGRslBf/cILNyGExJHZuDXapOl12X99HqReaNkt89PUtqlOJSsXYl5PCSGENGW8Iuysl7dm5eWnl98oLZ8byl9sb+7Vvfn03ueHavXsi3KfFOLZE12RX/lzSfIZYbfcZiWi6iYkvy6IMCGEpJuZE+GG1+VBX7/L8uByIazBW6ylTimyDfW8cWV9Je8D3PB6SgghpCljvTVapNbe9rTh9NMrL5Rluf3SjLJtsX3D1vwF0K/n9N0UX4SXyyhEeLmE2vULL9yEEBJHZkqE8wRflwd9/Xbr9Vs27XScfm2f9S/LMvXcfnQC7xfKbYOF11NCCCFNGZ0IR5KQiC6XUD/TDC/chBASR3768iF13feeVV+9+xmd7g+f0+U3/M9e2XX3PKMOHjqkbl94viz7Wl4mEu33t9LwurCycN4IIYQ0ZeZEeBbC+SeEEOKG14WVhfNGCCGkKYhwhOH8E0IIccPrwsrCeSOEENIURDjCcP4JIYS44XVhZeG8EUIIaQoiHGE4/4QQQtzwurCycN4IIYQ0BRGOMJx/QgghbnhdWFk4b4QQQpqCCEcYOf+EEEJmL6H/8wfJatoez/HPPyGEkOMrodcGm0YRBgAAgNGx3Atyv0jb14/9khBCCCEDBhEGAACIAESYEEIImVwQYQAAgAhAhAkhhJDJBREGAACIAESYEEIImVwQYQAAgAhAhAkhhJDJBREGAACIgHGJ8NGfvzlU+UC56TTVarV0TrkpsJ0QQgiJPCMX4YcffpgQQgghDWliHCJ8yWVXqo9+7Ex1+OgblXJZl/JLL99ZKR80N55aSLDOqbcE6xBCCCExZywiDAAAAHUmKcJHXv+Flt3fePtvVmTYSrAtl3p+2/65RZ0iAnziaeqUE0WGT1LnPeJsd2aLdU68UD20kvI8FeHOc8L5j/ctJ4QQQgYNIgwAADAhJj0jfOi1YxXpffng0cq6P1M8SB46/6RSPt1lvd1KbSmzj6vzTs2Xm8ofuVCdEGgf7NukqZwQQggZJogwAADAhJi0CEvcGeAN7/idVUmwFlh3FtiIrBVcO1Prf264qdxKbS2n3lLbZsW3qZwQQggZJogwAADAhJiGCEv826FXJsF5rPjWUojxSkW4UWb926bt55GbygkhhJABgwgDAABMiGmJsETk97IrdunbpUPbB0lIXCtlw94aXQrtaepG018wVsB94W0qJ4QQQpbJZEX4yKNq7/XXq+sle/eqR/eb8lEj4+x9VB0xqwAAADEwTRFefbzbom15OUtsZNafrbXy21QemGUWqfZvgbb1m8qr+0oIIYT0zwRFeL+avz6XX2unWorn89IxgAgDAECEpC3ChBBCyOxkciI8STlFhAEAIEIQYUIIISSOTE6Ecy19dO/1av7R/eqIb6i5uM7n24pbpud7s8b753u3Ul+/V83L9LGW3Hk1P783L5tX+4/s77XVdfLGps6juo7TFgAAYIogwoQQQkgcmaAI5+TS6sppIbwiyN4t06HZXFsuP6WtCG8p16a2SLHeVtTRUiyIUDNDDAAAUwYRJoQQQuLIZEXY4Ugup9eXYmtndG2MGOfb5nNJLsttfSu17rKLX95UDwAAYIIgwoQQQkgcmZoIF1+eJbc2iwiHvjTLzu4afbUy60ptk+D65U31AAAAJggiTMjsBQDSZGIifOTRver6+Z6MljPC+b/q7c1WWgtR7hU7M8il1Pa5NdoVX0QYAAAiABEmZPYCAGkyMREWad1ffj5YbnOW2WC7KRfYwJdlifza26b3yi3SNRHOafyyLEQYAADiAhEmZPYCAGkyQREGAAA4vkGECZm9AECaIMIAAAATImkRfuRCdcKJF6qH7PpNp6lWq6VOucmpQ8iM5rFvfUfn8KHXa9sAIE0QYQAAgAkxMyIsy62T1HmPeHUImbE8de8P1UX/13q1udXS2fKra9XC179RqQMAaYIIAwAATIiZEOGQBOuylp4hbpXbHlfnnejOGN+iTkGeSUKR2d+5f72ulGCbc9asUc8//kRZDwDSBBEGAACYEOmL8EmBmWAR3NPUjZV6ZuZYbp8+9Zai3F0mJIHIzK8vwTZ3nv+lsh4ApMlYRJgQQggh4TSRhAiLBJ+fC637WeHKbLCNFeOeJN94Kp8nJmnl+5ddGZRgyXc+/4WyHgCkychFGAAAAIYnCRE2AvzQ+Sf1ZnfdGeBACgH2Zo0JSSAvPv2cvg06JMLyxVm2HgCkCSIMAAAQASmJsP387wnnP54vi+T2me01M8ZF3cB2QiLOPRddXJPgW/7kI5U6AJAmiDAAAEAEpCXCkkKAteAa2S1vja7UE2nmS7JIuvnJnd9Tt3/yMzoP33xbbTsApAkiDAAAEAHRi/BKI1+S1efWaUJSDwCkCSIMAAAQAbMqwnxJFpn1AECaIMIAAAARMKsiTMisBwDSBBEGAACIAESYkDQDAGmCCAMAAEQAIkwIIYRMLogwAABABMQowgDQH64TgHRBhAEAACIAEQZID64TgHRBhAEAACIAEQZID64TgHRBhAEAACIAEQZID64TgHRBhAEAACIgehFe7Kh2u6MWzaomVAYwgyzl15jkzWPHTElB7ToBgGRAhAEAACIAEQaIjwMLC2rb+vVqc6ulc+7ateqx3bvNVkQYIGUQYQAAgAhIXYQXO23VykVBx9aT7bas1VadoqJu08mkLFPdynqRrCuNvT4r7TOVtW3dRdUpl4t2wXEBhkRmfzvr1pUSbHPOmjXq0NKSrlO7TgAgGRBhAACACEhahLV45lJriruZLHdV5pRV69altVzvZj2RdpFyqaTrG7mVMndZt2sY16wCDIrM/PoSbDM/N6fr1K4TAEiGaEX4r44+ogMAAHA8kLQIa/mU2VdPQHWZm3y730+/db8PKfe3+8t+Gx1nvwAGZGHXrqAES+7eskXXqV0nAJAM0YrwkcVNOgAAAMcDaYuwxRHiUH3BL29al5/ubc1uua0fWnbLAFbB0QMH9G3QIRGWL84SatcJACRDlCL8y2P71Us/+Pc6sgwAABAj3/rWN9TXvvY19ed//ufq2muvVVdffbX6yle+om6+6c9NjcGJXoS15FY/b6s/w2tuV856xqo6balXSHF5y7PFF9Wmda9cj+WXB5cbxgVYAfft2FGT4L0bN5qtiDBAykQpwq8tdXIJ/i2do093TCkAAEBciAT/8o3/Tb35s7+ufnHkb6g3Xv2b6ucvrVE7d+40NQYnfhHOEdnMRaByq7LeYGeCi7StFIfqu/Iq9FnvOl+g1c6yotyt32/ZH1fKAVbA/vl5tW/TJp3FPXtMaUHwOgGAJIhOhP/XXx1SL9//jlKEZfl/vXnYbB2E6ouxzqR+Lay/tMN5AwAAADPNV7/6VfXmz/+a+sVruQQf/Jvq2Mt/S/3swK+oK664wtQYnCREGAAqcJ0ApEskIvz/qV++8Xz+JuJudWTxs6UE20iZbJM6Urc/RoSn8dtfX4TNOrdnAQDMJtdfv1Ndc801+nboq666Su3atUtdeeWV6vLLL1eXXXaZuuSSS9T27dvVxRdfrL785S+rrVu3qrm5OXXhhReqizrFl+1YEGGA9OA6AUiXqYrwz174mjr0l/9dvXz/O2vy2xSpK22kbZgpirCHvaULEQYAmE3kc8G/OPw31LFX/pb6+Ytr1OvP/4p67Zm/o448+XfV4Z/87+rgX/6qevWhterlhb+vXrrvH6iffv8fqQP3/GP1/B3/RP3Zn/2Z6aUAEQZID64TgHSZqgj/8o2fqlcf+M9B4e0XaSNtwzSIcPDzQvaP8HvfSum2N7O6No2fe5JvyHRmhN3PNelYG2783JJ3Szf2DAAQPfLlWG+8aiT4hV9RR5/92+rIU4UEH3rs76lXH16rXskl+C3nv0XnwPf+sXrhzn+invvOP1XnnXee6aUAEQZID64TgHSZqggLw8pwfwkW6p8Rrjmlewuzdzuz/lZK28ZKsOmgsq0UWkeivb7qM8Jm32yB7SNfL+pWv40TAADiRm6Jli/H+plI8P6/rV5b+jvq8GIuwY//PXXwkV9Vrzzw99VL9/+DUoS1BH/3n6r93/5n6txzzzW9FKxWhEPlhBBCCAln6iIsDCrDy0uw0OfWaG82thBWt76dIS7+8H5NZB1xLZfdcZYTYSvWfvIKVrIltj0AAMSNfC5YvhzLSvCRJ/6uOvTjXIIfzSX4wbWlAPt5du8/V1u2xP8ZYUIIIWRWE4UIC8XfDg4LsM1gf1M4LMJWSrVkBoW1rTpdR3TL8tGJsJXdRtF1RTkk8gAAEBXy5VivP5dL8NOOBNvPBf+od0u0n6dv/ZfqC1/4gumlABEmhBBCJpdoRPjNnz0ZlF83Umd5QiJc/SxwTUiN1LbbUt58q3Pw1ug+IlypXxQUbcyMsyaX73I8TZ8ZbQAAiAr5huhBvhzLCvCz3/rn6pnb/oVauvlfqXPOOcf0UoAIE0IIIZNLNCJ87OXbg/Lr5tgr3za1+9Egks5sayG8jgiXoty/XaXNACJc7oukNy1sZNimEG87e+yWAQBA3MjfCw59OVYpwebLsawIP9P9F+rpb/5L9dSN/4f6/Oc/b3opQIQJIYSQySUaET767CUV6T302Ed13LLXn73U1AYAAJg+8veCQ1+O9eK9/7D3DdHmy7Ge2ZNL8C25BO/+V+rJG/5P9bnPfc70UjAuET768zeHKl82N53m/OK2yAnnPx6uW+YWdYque5q6sU/ZQ+efNGB/hBBCyOoSjQgffvzMUoD/6rUHTKnSy1aIDz9+likFAACYPpddul3t2LFDbd++XW3btk1ddNFFauvWrWpubk596UtfUhdccIH+e8Hyp5Lky7Hkc8FyS7RI8Gc3bzK9FIxDhC+57Er10Y+dqQ4ffaNSLutSfunlOyvly8ZK8Km3hLc3ZjARJoQQQiaVaET4yBOfrwiwj2yTOgAAALPIqEX4yOu/0LL7G2//zYoMWwm25VLPb9uUZWds/dniEy9UD+XlN57qlOmcpk4JlN3oirZdPvEkdYKtY/qTsep9ttQpN4W3McNMCCHETzQiDAAAcDwzahGWHHrtWEV6Xz54tLLuzxQvm363RT9yoRbWct3ULdYHnBEOinBVprXsuvW8bdxeTQghZJAgwgAAABEwDhGWuDPAG97xOyuX4DJWYJ3kQmoFtBYtq6sQ4YDsVqTY2+bvB0JMCCEkFEQYAAAgAsYlwhL/duiVS7AXMwsss7Y39p2JnZwIV/qxMX0QQgghNogwAABABIxThCUiv5ddsUvfLh3avqKExLUiuzajFWH/9ueaCNtYUUeECSGEeEGEAQAAImDcIjyKWOF0U5kBtuIZ2F69ZbmQ31rZgCL8+rHH1Xkn2na9uJJcxvmCLUIIIcQGEQYAAIiAFEQ4zlgpDs1EE0IIIeEgwgAAABGACA8Te1u1zUnqvEdC9QghhJBwEGEAAIAIQIQJIYSQyQURBgAAiABEmBBCCJlcEGEAAIAIQIQJIYSQyQURBgAAiIAYRRgA+sN1ApAuiDAAAEAEIMIA6cF1ApAuiDAAAEAEIMIA6cF1ApAuiDAAAEAEIMIOix3VbnfUolldEYP20c3KP8OUdU3ZShnFfkNSTPU6AYBVgQgDAABEQPQiLJJX+du9IxDHJiYmwl2VtdqqMypzHZcII9hTZym/xiRvHjtmSgr862Sx065cIzr6QpHnml8muOVZvgYAk2KqIvzBnVcNHQAAgFkkCRF2ZUzW8zfvY5HhUYjfIH3oYxihfIxivyEqDiwsqG3r16vN+XNdcu7ateqx3bvN1uVnhLtZS7XlNy3dzLlWFlWnXfwCRrbbci3RY7mgACDE1EU4727gIMIAADCrJCfCglNWnQmzs6zyht+V5d4MbKV+sN9cHPK21f6axhGqM25Zx9lfffuzW1fwZuikrhZjW2YE2RxjJxeW4IxdpU0eO2ZjX73jyrrF+SmWpULD8Zl90PtX7ku1HYwemf3trFtXSrDNOWvWqENLS7pO7Tpx0c+B0C9a5Lkn5fanwT7OZhUAxstIRNidsW1KCCnPu1s29z75qP7Z1E/xH03vRUFnVP+RmM8O6d/mrYjei1wt0ewjAABMmyRF2H8jb5HXJWtooWVPELqZ14fe7slv6DWz7NsX7hy7v95YFSrHVIix7UOPWe5rk3BW2/T669eXOS792u0s9zs+26+/L03tYCTIzK8vwTbzc3O6Tu06cShng0vse0L7fPSvn4brCQDGwshEuB+rEeG5O3aot5z/FnXND25YXoTti4F+ccnXy1eKVWD6GoVk2t/yDtyXGXvZwxjhPgIAwHRIXoTta7FNWbdXp3cbaCGKjZ+J9MfSffcZJ7RvZb0+YuG28/vQ7fO2ob4toTayPkhf/Zabjs+tJ/jrMFIWdu0KSrDk7i1bdJ3adWLRj2PTc0+e//JLEF98/XUAGCdRi/BND9yuJfjXtr5NLTz9xOAibNdHIcIjZFgRljcMUh8RBgCYfZIUYVumX3d7M7h+3UKAQ2/yG4TYH0v3n9dpGsevL5iyrp2NDeG28/uQdTum37cl1EbWB+krtKzr9Tk+t43gr8NIOXrggL4NOiTC8sVZQu06MdRng6sErwkeT4CJEoUIi+TKTzdyO/Rb596qRbj78J26bGARdsXQbrMp/4OxL74m+kUyUFb21TW3s3gvUFLP9tk4VkFQhE3/NnableAysi9N/SPCAADJk54IF6+Z+uXT26Zf79y65vWrfJ3K17Pei2n++uq8tgqh/uzrYHCcPrdG54uNUlLpzzmenKYxq0ib3r739meAvkLL3lhlfw3bK33AWLhvx46aBO/duNFsbRBheVy8X+4sdjLnOd573hRCXJSWzxMAmAgjFeFS0JwI/UT4rh//SMvuydd9SL34yht5/0o98cJL6tcvebsu337PTl0mWVaE3YT+I3GEsRDN6gtvqMxtU1nO0f9h5evFUMWLXjmu3SdnP2z98sXYSrCpU+3P7k9vvUKf/QIAgPRIQoTlNatM6DW0SDvLPEHzZde8Ztr6/uuXP5bTV+M4XpvKl2WZ8YLjuPtZ6cOIjF/Hx76WS/+N+xPoq2E5eHx2u9tG8NdhLOyfn1f7Nm3SWdyzx5QW1K6T/NGQX8rUnmvO80TSe2/nXgtVeQaA8TJSEW6inwiL/G7Y+c5Shve/dES9++r36PUzb/tUPl5vlnhZEW56MbDbTeQ/Jyuddr2oVi+z/3EV6+Y/Kz2O94UH3n9wZfqIcE107X6agqAIB46luo8AAJAi0YvwapDXKYQNZpCRXicAMFGmLsJ5d1p+rQzL54Hl5/uv/YNyhthmJSJsZTIojK682rZ+mdem6K+tOt2qtNZmewOsVoQbj8U/LgAASI5ZFmF5/ar8UhdgRhjldQIAkyUKEZa4Miy3Rcu63WYzvAjbWdvidqywrLqzvBanzJdMM1a7LX05t3mVM7XObS25LLtD1cb3+rbb7ZuF6nqfY0GEAQCSZ5ZFGGBW4ToBSJeRifByCSHleXdlRH7lzyXJZ4TdcpumfkoJrYlwjpFELYpaXgthtLOrRQq5DJXVJdMKaR5/vFKGvT4MQRF39q+2zQq5RGy44Vjq+wgAAKmBCAOkB9cJQLqMRIRXii/Cy6VRhAEAABInRhEmhBBCZjVTF+FhAwAAMIvEKMIA0B+uE4B0maoIAwAAQAEiDJAeXCcA6YIIAwAARAAiDJAeXCcA6YIIAwAARAAi7CBfPhn6AsxhGLQP54so+RNPMCxTvU4AYFUgwgAAABEQvQjX/jLCGMVxYiIsf52h+hcehqJyTjLVrZ0j508qQtIs5deY5M1jx0xJQe06KcmfW+7zr/LccJ9zzl8I4fkCMFEQYQAAgAhIQoQDb+zHIsP+WCthkD70MaxSPtxx/DFltnm1xwFT5cDCgtq2fr3anD/XJeeuXase273bbA2LsP1zmb3HXv70piO/zvNC/nSnvYZ0O25LAJgYKxbhuxbvUDc/sDuY7z7+bfXw8w8RQgghZMAkJ8KCU1a++dexb/qLv73fe2/fm4Gt1A/2m6nM/t1+ZwYtPI7gzqzlY3ac/dW3P7t1hWp9vQ8ybllmBNkcYycXluCMnXte3GWNjMEsX6rI7G9n3bpSgm3OWbNGHVpa0nVq14ml8lzwRLjc5j0/as8fABgnKxZhEd65/3F+Y27/yz3BF3pCCCGE1JOkCDeJnointd/QsvTltOtmXh96uye/IUEo+/aFO8furzdWhcoxFWJs+yhn53R7r28Xt49Kf6aP0H5DEsjMry/BNvNzc7pO7TqxeM8F+/wqfslin9v+9dNwPQHAWBibCEuQYUIIIWSwJC/CRhgrM6xend5toFYKBhHUHN13n3FC+1bW6yMWbju/D90+bxvq28Xvw983XQlSZGHXrqAES+7eskXXqV0nFu9503vuF7+0KX6BgwgDTJOxirCknwx/cOdVQyfUDyGEEDLKbLriEvUf/uRM9XtnfEr9/tmb1e9+7JPqtz9ylnrHn56tfv8Tm9S7zvi02vCRT+j81h9/XP3J+V8K9jNMkhRhW6YFMHTrZ0EhAaE3+Q1C7I+l+zdSGhrHry+Ysq6d2Q3htvP7kHU7pt+3S78+IGmOHjigb4MOibB8cZZQu04sfZ8X9lZp75rg+QMwUcYuwpImGRaxzbsbOIgwIYSQSUQk+OJ771XnfOu76r9ddaO66HvfV9c+9qja+eAD6hM33Kq23P5ddfWjj6ir//JR/fPfnX52sJ9hkp4IFxKrHdPbVrslWLbnddu9e51V1rPZ6ucnhVB/MlDjOH1ujc4XRcTLsV0q/TnHk9M0Zg13+3J1ITnu27GjJsF7N240WwedEa4+t/Q2I8B8WRbA9JiICEtCMjyoCN/75KP653Etwt87U73t35ypbgttI4QQMtL83hmfVlu+fac69dN/qj5zzsnqQ1/8ovrG/mfUJ2+8Vf1+9n71+x/9iLrqkUfUTc8tqW8+/6x6xxmfCfYzTJIQ4fzNfHnbr/flU/KG3m5rZ5knhL7s2plgU9+XVH8sp6/Gcbw2lS/LMuMFx3H3s9KHmanz67j49fvVhWTZPz+v9m3apLO4Z48pLahdJzlaaMvnhRHdynOl6VpwZocBYOxMTIQlvgwPIsJzd+xQbzn/LeqaH9wQFmERxPI/EMl71Xa/zkqyIvG8VZ31b9x96eVtm28N1DcZZCxEmBBCJpb/ePZm9d92fUNt+sIH1BuPZuo9G/+L+srjP1Gf/eZe9bsf/oB671ln5iL8qPqLp59SNz/39PEhwqtBvtQKQYQZZKTXCQBMlImKsMSV4eVE+KYHbtcS/Gtb36YWnn6iWYRdQbzmvaoVgzAOI66IMCGERJXf/fgn1Zf/5/fVe8/+pHrHqX+oNl6+U123+GN1/RM/Vp17vq92/OB+lW3dpt59xllq6133qHd/8pxgP8NklkXYvf0TYJYY5XUCAJNl4iIssTJsRVgkV366kduh3zr3Vi3C3Yfv1GUDifDz29X7zKzwbZvf5szKvk2d9b2iTqXctK2V2X7lZ2WWude/Htu2cfoP75cpK+vbPquzyDJzHNzvUH+EEELGkg0fOUvd+OyS+sAFF6s/uugKdfPzz2oJ/vqTP1HffP4ZdfVjj6nf+eMPq/906gZ1+q7r1Hs3nxvsZ5jMsggDzCpcJwDpMhURlty1eIcW27t+/CMtuydf9yH14itv5P0r9cQLL6lfv+Ttunz7PTt1mWQQEdYSGRJGmSk+ebuR0Z7Ybj85X24qM/1sP7ml3neN148rxBJfVP11Xb/Xj95P3U+orhN3v5vqEEIIGWmsCP/R3MXqjK9er77z2qvqL55aLGX460/+WJ19/Y3qQxduV7sefED97ic+G+xnmCDCAOnBdQKQLlMR4evu/6p+0RexFfndsPOdpQzvf+mIevfV79HrZ972qXy83ixxowiXs6d5fBmtbSuEtPpZ4kCZK56l/IoUOzO0bt/92jet2/rBbU6/ss2vQwghZGyRP4v0F0tPqA9+6WL1b//zH6sP79ilvvLIw6UM35Bvu+mF59StL76gbjmwX234+KeD/QyTGEWYEEIImdVMXIStBEtEbPPutPxaGZbPA8vP91/7B+UMsc0gM8KVcvd25Vq9ZYS4Ul9uX5Z6+XZbtpyY+ttD6yER1uWB/fbbE0IIGVt+78xPq8/e9m118lmnqxu/8gfqc188WX1422W59D6nxXdLd6961xmfVH947gXqyoUF9a6zmREGOB7hOgFIl4mKsCvBEivCEleG5bZoWbfbbIYWYae8vGU6L39f+Q3OIri5dF4TLvPbv+/k9zrf/lxIc3nLtJ/aflXr126Nbpgddvc7eJyEEEJGHvnW6A9f+XX1sU/+J/XG4Y3qse9+SP3bD2Tqi3u/rbbk+e3TP65+2P2g2tb5f1V26Vfz1xA+IwxwPMJ1ApAuExNhX4IlrghLRH7lzyXJZ4TdcpuhRDiPfLbX3l78NpFYXc/O+ppyLbaBMr9fV1YrZb12tduy/f2q1K/2ZfdVxg7ud6g/QgghY8m7zvi0umDfPeoDnz5Ldb70fnXG505Rv/2xT6vfO/vzOv/3f/1Tdcm2D6gzNv2hOvuGW9V7PrMl2M8wQYQB0oPrBCBdJiLCIQmW+CK8XIIiTAghhIw4v/XHH1df/cnj6uJ7f6D+6KKr1Flfv0XdtP8Z9a1XX9S56qGH1H+5/GvqzOu+qT9L/P989FPBfoYJIjxCFjuqPam/Wyx/I9n88rrxT0RNcn9goiR9nQAc54xdhJskWCJiO2xC/RBCCCGjzJ9c8CX17/77J9S7zv6cet9nz1Pv+cwX1TvP3KzeccZndKRc/mTSezZtUf/hTz+lTv7M54P9DJPoRVhkToTPsz35G8Gt2CRvYuLZVVmrrTrLDTSu/YlJsO3zQydT3cq6KTNVU2Qpv8Ykbx47ZkoKatdJSf7cqDw28lwJnYumcgAYN2MV4X4STAghhJBekhDhdpa/uXfET5e145Exy6QEUcveAPIyqf2ZNu5x+scsM+cJnoMDCwtq2/r1anMuqpJz165Vj+3ebbaGRXix0y7E1jle+YWR/R2S3m5WmsoBYPyMTYSRYEIIIWTwpCHCHdXN36y3jQnrN/GdnvCUAqBjhbmY8bJtdD/+LKrpuyOzy6a99gFfpuy6/ilSbusuqk65bOv1tvf2xWwzY5Tlpt9i/IDYVtrY7e5MXh53P4VKG2d7qC89fp/j0VUC59bsd3E+AufPbxfax8p56rXT22y7Yc6Te5yV8eR8DfBLg4iQ2d/OunWlBNucs2aNOrS0pOvUrhNL5fi9Yy+3NZUDwCRYsQjftXiHluFQbnvoluCLPCGEEELCSUWEyzfvdr3pzbvMAPZsLJcqecMvgudJsKC3OxJmZw/9vt0xrZzpz+g6y/72HC2Dup8G8dD1nfErSBtPLN3jcvevpNqmV6+hL3d/Q8ejaztIuW0X2v/Keegdbzdzjl1wxxX02FJnJecpx9bzl/WqfQzSQWZ+fQm2mZ+b03Vq14mlcvze+SzXm8oBYBKsWIQBAABgdKQjwuJLzuyhLz95uZ1ddMXHzkyWM8MunjSV64OUh5ZD7UQw9E9n/3RMuVvfpakvuxxqF2oj6019ueX9lt39dvtz6wnluoiVOUazqYLfTtfPxbjrjWX7qNX3cLfLstu+X7tIWdi1KyjBkru3bNF1ateJpXKumoS3qRwAJgEiDAAAEAEpiXAhOeYNuy3XZc7sYkUEcvRsYwQi7JZbmsqFpr7s8iD92fWmvtzy0LKuFzi3/k+zudKHRgTLyKwp0QTrGRGulBtq9T3c7cvVTYCjBw7o26BDIixfnCXUrhNL5fg9wS23NZUDwCRAhAEAACIgKRF2seXe9uqtsPYNvxEtvxO/b7dPRxTKPt36oWW3TBebW5D1+IFbe736Vapten3plYZ21ePsnYuGvkLH4C5749TOg7fdbZf17Ll+W7rfrrwVeyXnKcfdvlzdRLhvx46aBO/duNFsHVSE5dSGn0N8WRbA9ECEAQAAIiB5Ec4X7S3TeuY3y0y5J1Xl51Ad/L6ddS0Hfp9u/dCy/DRtdOx2IbTN7SNEpc2AM3hmBlzSOxc5ob7cfhqWg+fWbnfbCOV6ce7Ldv5vIKSes712bO620Dgulfp5P/3qJsb++Xm1b9MmncU9e0xpQe06yXGfs5Liue8+Fu7zv6kcAMYNIgwAABAB0YswzB4zJKvTgusEIF0QYQAAgAhAhGHiIMKrhusEIF0QYQAAgAhAhAHSg+sEIF0QYQAAgAhAhAHSg+sEIF0QYQAAgAiIUYQJIYSQWQ0iDAAAEAExijAA9IfrBCBdEGEAAIAIQIQB0oPrBCBdEGEAAIAIQIQB0oPrBCBdEGEAAIAIQIRHyCT/LFA3U61WSyfrmrJY4M8jjZ2krxOA4xxEGAAAIAKiF2GRKhE+z/a6WV4Wm2xNTAC7Kmu1VWcUA41jn1fS54r2Y1F12oHngX3OmLTlRJkyvWwZx7GPmKX8GpO8eeyYKSmoXScl+XOjckzyXLHnIsvXAGDaIMIAAAARkIQIt7P8zb0jfrqsHZ/ETEqstNSNSGrGsc+TPA/+c6P2S4J8XX6JEqo7qf1cAQcWFtS29evV5lxgJeeuXase273bbA2L8GKnXQivc0zyCyP7OyS9PbrbBwCOPxBhAACACEhDhDuqm7+Jt7N5+s19pycxpQDoWNEpZsLKGUDpx59FNX13ZHbZtNee4AuSXdc/RaZsXTMjWWnX297bF7PNjFGWm36L8QNiW2ljt7szfHkC+1k7HrutbGf3q7f/knaWFcdZ1rdjSj2zHNqnyrh5mVnX/ehbuIvxKo+Tu9+CbVPpq0iTu0l/8vjK86E30yvnx+63g+1f9sd26O5nRMjsb2fdulKCbc5Zs0YdWlrSdWrXiaVyTN65iPR4AY43EGEAAIAISEWEc90p3tTb9aY39b7oaBEQkfMkWNDbHdGStqG+3TGtRDqCV2lXSqY0y8VP99MgJLp+k+gVwts7FGc2z7Yv1nr4/dn9ahrfX3bqyXhZLsZFX3l52U9gn/xxbZ+63IzrLud0877tsqbSJnQMPs5j6tXRt83nfVRmP23/+WI5S+qUxYTM/PoSbDM/N6fr1K4TS+WYvMe9tg4A0wARBgAAiIB0RLgnODWJkeW83M4gulKkZS0vq3w21OKLkF0fpDy0HGon4qF/OvunY8rd+i5NfdnlULtQG1nXbQPju3V0AznHhVxqUZVtcrLdn6F9CpY7Y2gKia6WOdg+Qn2565ZKufTd+wVEif5lRT6mv+9NY0XCwq5dQQmW3L1li65Tu04stfPiPwYN5x8AJgYiDAAAEAEpibBetm/kXZlxJagiAjlGhqYuwm65palcaOrLLg/Sn11vqi942/RMcDcXJl1mbonOz2FwBlXWQ8dn1uV29sqsrKZBiG0fDX35+25/weEm+Bjr8er7qI/Tub0+Jo4eOKBvgw6JsHxxllC7TiyV4/TEt+FcAsBkQYQBAAAiICkRdrHlAcHpzQhbEZCfgRlDv2+3T0cgyj7d+qFlt0wXWxEs5K/mhF79KtU2vb70SridX16uN4wvSB1PluQLpaxULnZyCc4yc+4a9qlx3LyF/fyu9Fs+AIFb1W2bPn31kPbe8djbo6W+u6GpX3Ms7t0DMXHfjh01Cd67caPZOqgIF+e/9ngBwFRBhAEAACIgeRHOF8vPhObpfeGTJ396ZtgRPsHv21nX0uD36dYPLctP00bHbhdC29w+QlTaDDCz55e765W+zPi6Uu/8FfIr582RVCuYZjW4T/3GNY9Du5OLcNnOjuVg2/TtyxAqK/e7kGQ7jv/FZJU2/rFFxv75ebVv0yadxT17TGlB7TrJcZ+zkuK5b4Rfx3v+A8BUQIQBAAAiIHoRBoAaXCcA6YIIAwAARAAiDJAeXCcA6YIIAwAARAAiDJAeXCcA6YIIAwAARAAiDJAeXCcA6YIIAwAARECMIkwIIYTMahBhAACACIhRhAGgP1wnAOmCCAMAAEQAIgyQHlwnAOmCCAMAAEQAIgyQHlwnAOmCCAMAAETAcSPCix3VbnfUolktaSqfBIOO3c1Uq9XSybqmbDUMMu40z4uPf/wx7duUGNt1AgBjBxEGAACIgOhFWKTHSFAvbdUZ1oKa5GmaUjXQ2F2V2eMd1b4O0s+4zsvQ/QaO3+1jXPsZCUv5NSZ589gxU1JQuU7kFwXuOZBzspJrBAAmAiIMAAAQAUmI8ChEp6mfaYrUIGNrqclyHRwhg447rfPiEjp+d99i2c8Rc2BhQW1bv15tbrV0zl27Vj22e7fZWp8R7ma9uwVkuY0FA0QLIgwAABAByYqwKe/kb/ort83qTe367LGun6msHSp3pMpv51Lro3qrbrEvRtqa+qqU5+k7tsyGOnUlUr8yXpHylulhx3UZaN+c43PORdZdVJ1yWSpIlabHYZljKOl//Iv5PzumRMtfZV+rY7qPT2XfdF/xILO/nXXrSgm2OWfNGnVoaUnXabxO9PE7vzgInQ9dHO/xA8w6iDAAAEAEJCHC5Rt55427KS/lyb891CLlUknX90TA9qPbiXR5AuH35/Wh+5Y2/r409lWIXVlvkLFDy/IzeOzDjuvSb9965fq8yYreB3Mu9Hlwlmt957iPg2zX7UPH4OHuq9vWL5PlpuOXn/6xOfW6mdMmAmTm15dgm/m5OV2ndp3k6Jngdrt3nH3PR7zHDzDrIMIAAAARkIQIl6Lj4Je76/qNfkCc/foiA7bcb6PjCYLfhxaNXAC7ob4DffntBxnbbePWH6afpvpmVdOvT7/c77Pfsrsvbn9uPcFft/j9+W39ZXc8ncDx68fNbDMlMbGwa1dQgiV3b9mi69SuE8E/zqbzEfnxA8w6iDAAAEAEzJwI6zf/zqytW16TBEeS/O0hanX6iHCoL798kLHdbU31l+unqb5Z1Qzap6z7chla1vX6PA5uG8Fft7jlobZNyy5N5ZEK4dEDB/Rt0CERli/OEmrXieAfZ+NxWxBigGmACAMAAETATIqwU16/Bdopd2/VNVLQu600gD+mvZ3XL2/sy4izqVjuW7+x3b7tsj9euT7suC6D7Vv9vOnCZfex7K9he6UPF7c81FaWS5FrOH6/73w96xm66rQdYY+E+3bsqEnw3o0bzdYBRbjP+Yj9+AFmGUQYAAAgApIQ4fzNfPX2zvyNe59ZWPmspK3bzrKi3O/HtnXloamOpbYvRsDcPixNfenP0xZl5b71q+/2bZf98fw6oX6axnUZaN8Cx9yw3Pg4uD+ljeCvW0J9e3XtOPUvy8oTqJ+30IJY7lukFrh/fl7t27RJZ3HPHlNaULtOhNpx5oTORyLHDzCrIMIAAAAREL0Ix0RINACmQNTXCQD0BREGAACIAER4CBBhiISorxMA6AsiDAAAEAGIMEB6cJ0ApAsiDAAAEAGIMEB6cJ0ApAsiDAAAEAExijAhhBAyq0GEAQAAIiBGEQaA/nCdAKQLIgwAABABiDBAenCdAKQLIgwAABABiDBAenCdAKQLIgwAABABx40IN/3po2n+SaRBx+5mqtVq6WRdU7YaJnnM/cbyj2uaj0VijO06AYCxgwgDAABEQPQiLHJkZKmXtuoMa0tNkjVN+Rpo7K7K7PGOal8nccx2jMaxAsfl1p3EPibAUn6NSd48dsyUFFSuE/mFgnuu5Nyt5BoBgImACAMAAERAEiI8CiFq6meawjXI2FpqslwbR8gkj7nfefePy607yX2MkAMLC2rb+vVqc6ulc+7ateqx3bvN1vqMcDfr3S0gy20sGCBaEGEAAIAISFaETXknf9Nfub1Wb2rXZ491/Uxl7VC5I19+O5daH9Vbeot9MXLX1FelPE/fsWXW1KkrkfqV8YqUt0wPO65LqK0eq3fMWXdRdcpl26zpfPf2tTpW/+NazP/ZMSRa6hr3rXreK/tSGzcNZPa3s25dKcE256xZow4tLek6jdeJPk/OLxhC500Xp3+eAFIFEQYAAIiAJES4fCPvvHE35aUA+reHWqRcKun6ngjYfnQ7kTNPIPz+vD5039LG35fGvgoBrEjrcmOHluVn8NiHHdeloa0eyxyzPl5nudZHjnu+bftQPbc8VLfSrt++ecfl1OtmTpuEkJlfX4Jt5ufmdJ3adZKjZ4Lb7eWfhzNyngBSBREGAACIgCREuBQiB7/cXddv9APi7NcXGbDlfhsdTxD8PrRo5GLYDfUd6MtvP8jYbhu3/jD9NNU3q5pB2vZbdttJud3u1nMJ9RUqs8tu/zqB49KPh9lmSlJkYdeuoARL7t6yRdepXSeCfz6aztuMnCeAVEGEAQAAImDmRFi/+Xdmbd3ymiQ4MuVvD1Gr00eEQ3355YOM7W5rqr9cP031zapmkLahZfnZ73y7bVzc8lDdpmWXpvLERe/ogQP6NuiQCMsXZwm160Twz0fj+bEgxADTABEGAACIgJkUYae8fgu0U+7ewmukoHdbaQB/THt7sF/e2JcRZ1Ox3Ld+Y7t922V/vHJ92HFdGtqGxneXvX2pnW9ve8lyfclyKWgD7JuQr2c9I1edtiPoiXHfjh01Cd67caPZOqAI9zlvs3KeAFIEEQYAAIiAJEQ4fzNfvb0zf+PeZxZWPitp67azrCj3+7FtXXloqmOp7YsRNbcPS1Nf+nO2RVm5b/3qu33bZX88v06on6ZxXUJt/b4Dy43n22/vEurLq2v7rX9ZVp5g34X4lfuSuN3tn59X+zZt0lncs8eUFtSuE6F2PnJC523GzhNAaiDCAAAAERC9CMdESDQApkDU1wkA9AURBgAAiABEeAgQYYiEqK8TAOgLIgwAABABiDBAenCdAKQLIgwAABABiDBAenCdAKQLIgwAABABMYowIYQQMqtBhAEAACIgRhEGgP5wnQCkCyIMAAAQAYgwQHpwnQCkCyIMAAAQAYgwQHpwnQCkCyIMAAAQAceNCDf96aNp/kmkQcfuZqrVaulkXVO2GlZyzOM+T/4xTvNxSYCxXScAMHYQYQAAgAiIXoRFiIwg9dJWnWENqUmspilcA43dVZk93lHt60r6GbbNUPUDx+i2X8n+zghL+TUmefPYMVNSULlO5JcI7vmR87WSawQAJgIiDAAAEAFJiPAoJKipn2lK1iBja6nJclUcISs55nGep9AxuuONc+xIObCwoLatX682t1o6565dqx7bvdtsrc8Id7Pe3QKy3MaCAaIFEQYAAIiAZEXYlHfyN/2VW2r1pnZ99ljXz1TWDpU7wuW3c6n1Ub2Nt9gXI3RNfVXK8/QdW2ZKnboSqV8Zr0h5y/Sw41pMn719sWK6qDr5MXcHHtM5ftNf5fHwx13mGBf1+L1tWvAq41UfR/cx6D9uvMjsb2fdulKCbc5Zs0YdWlrSdRqvE31u7GOXEzpXujjNcwMwCyDCAAAAEZCECJdv5J037qa8lDH/9lCLlEslXd8TAduPbidC5gmE35/Xh+5b2vj70thXIX0VgVxu7NCy/Awe+7DjuvTayrnJslz4df28fNkxe+X6vMpKZV97+9TN+7XLJe7+uO38MlnW4wWOUX76x7jcuJEiM7++BNvMz83pOrXrJEfPBLfzx6480H7nKs1zAzALIMIAAAARkIQIlxLk4Je76/qNfkCc/foiA7bcb6PjCYLfhxaNXIy7ob4DffntBxnbbePWH6afpvpm1dLNCsnXYiR1rNC6Ymvq9t2XypiFKNfOpYvbR6hff3mQYxxk3EhZ2LUrKMGSu7ds0XVq14ngn4Omc5XwuQGYBRBhAACACJg5EdZv/p1ZW7e8JgmOQPnbQ9Tq9BHhUF9++SBju9ua6i/XT1N9s2rRM8Hd/Jj0NnNLdNfMDA86pqwPK6Zu3VC/TcsuTeUJSt/RAwf0bdAhEZYvzhJq14ngn4PGc2JBiAGmASIMAAAQATMpwk55/RZop7wy01lIQe+20gD+mPb2YL+8sS8p70l6uW/9xnb7tsv+eOX6sON65P1k7Xb5RUuLnVyCs6xoN+CYtfMqffZ+K5HLtfNLCovbt9OuUlbKWsMxuvWFfH3ZcSPmvh07ahK8d+NGs3VAEe5zrlI+NwCpgwgDAABEQBIinL+Zr97emb9x7zMLK5+VtHXbucjpcr8f29aVh6Y6ltq+GDlz+7A09aU/V1yUlfvWr77bt132x/PrhPppGrdCVZhL0Zflgcf0z0khY+XYIePy+5JltyzHPqb1L8vKE6hfHEuvTorforx/fl7t27RJZ3HPHlNaULtOhNo5yAmdqxk4NwApgwgDAABEQPQiHBMh0QCYAlFfJwDQF0QYAAAgAhDhIUCEIRKivk4AoC+IMAAAQAQgwgDpwXUCkC6IMAAAQAQgwgDpwXUCkC6IMAAAQATEKMKEEELIrAYRBgAAiIAYRRgA+sN1ApAuiDAAAEAEIMIA6cF1ApAuiDAAAEAEIMIA6cF1ApAuiDAAAEAEHDciPO0/fTTo+PyJJhiAsV0nADB2EGEAAIAIiF6ERQxbLdWqpK06w5ri8S7CCHaSLOXXmOTNY8dMSUHlOulmquU+tvqaWcE1AgATAREGAACIgCREeBQCN20RHHR8hBVyDiwsqG3r16vNrZbOuWvXqsd27zZb6zPC3aylsm5vuY0FA0QLIgwAABAB6YpwV2W5IJRv+KWezIJ1pX6msnZvBlkLgtuPrmu3Z3lPve2dXCIqZWW98AzbYqdttueR/t1xBLuuf7r75fRXGcf0Uyt397PXT9ZdVJ1yWSp4+2THqeyHPc4+7dxjgIkis7+ddetKCbY5Z80adWhpSddpvE70c8Y8VwS9bh/r3nOOxxpgeiDCAAAAEZCECJdv5L037uWbfpFBR/hcyZTbRqWOlOt2hUBX5E9WzDi2vBBtTyh8YSjHL+hm7jgGu67reiIS2J/eOP320/Sjj81Z9vdPkHLbrtwPZzzbTpd7x2KWYbLIzK8vwTbzc3O6Tu06ydEzwfl1UD62+jkUeA7zWANMFUQYAAAgApIQ4ZDgGezMVmVmuFJfZCCXRT1TbCTA3W6lIFjuCbgrFZpCVivloX6GHXfQ+v2W3f12+3PrCeV64FhgKizs2hWUYMndW7boOrXrRAg9tnmb+nOYxxpgmiDCAAAAEZC6COsZzfxN/VhEuN+4FRyxaOonVL7a+qFlXa8381zrz20j+OtI0tQ5euCAvg06JMLyxVlC7ToRln1sfXisAaYBIgwAABABaYuwvJGXN/FGdqWSX9+99VeXF2/+g7ccV8ap1guSt8l6xlncni3C7YhFeQu01385rrvvtnzQ/Qwth8Zxy73tbrvasZSVYNLct2NHTYL3btxotg4owk3PYR5rgKmCCAMAAERAEiKcv5mv3t4pb9y9N/l6ZtjMmFbqGil1JaFSJ7Dd4vflbzeiYbfbWWktn7Ysy0rRbOzLzGpX6kv5cvvZsCyfFa31Z7e7bYRyPXwsMD32z8+rfZs26Szu2WNKC2rXieA/toKUOY+r+0sWHmuA6YAIAwAARED0IjwsIRkAmDFWfZ0AwNRAhAEAACIAEQZIj1VfJwAwNRBhAACACJg5EQY4DuA6AUgXRBgAACACEGGA9OA6AUgXRBgAACACYhRhQgghZFaDCAMAAERAjCIMAP3hOgFIF0QYAAAgAhBhgPTgOgFIF0QYAAAgAhBhgPTgOgFIF0QYAAAgAo4bEZ7En1XiTzfBhBjbdQIAYwcRBgAAiIDoRVjkstVSrUraqjOsbaYswqvt12+vz6l7Drsqa2WqGxrHK1vstCuPRdt2ovu05XlftTKnLgzMUn6NSd48dsyUFFSuk26mWn0fXwCICUQYAAAgApIQ4dVIoGVU/fRjEmOsCCO6Zk1ktt1uq6xXUOx3aP+dMi3Ble3SryfD5XbZ5sl2OSAsx4GFBbVt/Xq1OT+/knPXrlWP7d5tttZnhLtZq3w8ZZlfOgDECyIMAAAQAemKcEDCRLy6Uj9TWbs3E6kFwe1H17XbndnLfHsnl4jwjGbDDFulTp5lx+jtW9ZdVJ1yWSpIFXfG1Yxp9s2KarGPfdrZfXDoZr3972b5/nSz3rmzy3acorSgLPPF1uC2qbSX+j35hsGR2d/OunWlBNucs2aNOrS0pOs0Xify0z3vet0+X3qP33LPFwAYH4gwAABABCQhwuUbee+Ne/mmX4TSkUZX2OS2Uakj5bpdIdAVgZQVM44tr4lc2d6l2levTr8xzL7p/XKWQzIi5badbPf30bbT5b191aJrli2yD4X45ucqM/toxixnE03/lXMtsWOE9lEfqxnPqyP96vblDsMgyMyvL8E283Nzuk7tOsnRM8HuTL/72Aj28Rng+QIA4wMRBgAAiIAkRDgoYAV2ZqsyM1ypLzKQC6eeKTYS4G63UhAsd2RQxxOGUJtBx+i37I7p9ufWE8r1Qrxr++cida1UF9arOm2pb3+aOm7/gi0LbdM0i3CJlv58/xDigVjYtSsowZK7t2zRdWrXieCff1nP2/Sev/Y5MsDzBQDGBiIMAAAQAamLsJWssYhwv3GFpjahcn+M0LKu58xmu+XuT7O50oemn+AYYc3Pl/XRxU6Wj5WX2z5q/eWUZeY8VjbmuG1C7UvM+GYNmjl64IC+DTokwvLFWULtOhH889/38RD6PV8AYFwgwgAAABGQtghbuXIkza/v3j6sy4s3/z0ZdG5broxTrRfGGTdH9zXoGKFlbx/K/hq2u+2ynj33bhP3kM8Jy62z5bb83Mh68y8Rcpyy3vFZiuMMtpdl9+SF+oZG7tuxoybBezduNFsHFOGm53Beb5DnCwCMB0QYAAAgApIQ4fzNfPX2Tnnj7r3J1zPDuRTX6pvZLlcSKnUC2y1+XyGRMzPSknYmYjngGA3L5edq3f7sdreNUK4X56Js12A1NZGV9nn98hz6/Qteme7DGavStiyX4xXB6tVr/LIxaGT//Lzat2mTzuKePaa0oHadCE2PX/kY5Bni+QIA4wERBgAAiIDoRXhYQjIAMGOs+joBgKmBCAMAAEQAIgyQHqu+TgBgaiDCAAAAETBzIgxwHMB1ApAuiDAAAEAEIMIA6cF1ApAuiDAAAEAErFaEQ+WEEEIICQcRBgAAiIDVirA/m0sIIYSQ5iDCAAAAEYAIE0IIIZMLIgwAABABiDAhhBAyuSDCAAAAEYAIE0IIIZMLIgwAABAB4xLhoz9/c6jy5tyiTmm1VCuUEy9UDwXbjCN2P05TNwa3E0IIIcsHEQYAAIiAcYjwJZddqT76sTPV4aNvVMplXcovvXxnpXzQPHT+SVqATzj/8eD28QYRJoQQsvogwgAAABEwahE+8vovtOz+xtt/syLDVoJtudTz2y6XoAg/cqE6QQtqL+V2u01mjm86rZTYG0+t1peccpPpT9dztplZ53qbcF/TkXRCCCGpBBEGAACIgFGLsOTQa8cq0vvywaOVdX+meNAsPyP8uDrvRBHSk9R5j+TrpQifZGQ5l1cruqfeottYkdUibOqX/Zu6xXp9Rni6M9SEEEJSDCIMAAAQAeMQYYk7A7zhHb+zagmWNImnLe/FE2FHXivi663X+zHR0twswjYIMSGEkOWCCAMAAETAuERY4t8OvRoJloRE2C8rxNafEe59qdYgIhwW2obPCPu3UpuZZkIIISQURBgAACACxinCEpHfy67YpW+XDm0fJiFRtSJblDXdGt0T4bA4GzEupdaTXZ1lvizLjoUIE0II6RNEGAAAIALGLcKjTHjG1gqq5CR1wjIi3JPlauwMce926l7seHb8Iqep8yrreSrjEEIIIfUgwgAAABGQkgiPPlaKG2Z5CSGEkBEHEQYAAIiA40+E3RlkiZk9DtYlhBBCRhtEGAAAIAKOPxEmhBBCphdEGAAAIAIQYUIIIWRyQYQBAAAiABEmhBBCJhdEGAAAIAJiFGEA6A/XCUC6IMIAAAARgAgDpAfXCUC6IMIAAAARgAgDpAfXCUC6IMIAAAARgAgDpAfXCUC6IMIAAAAREL0IL3ZUu/J3f1sq65pto0bGanfUolkFiJXadQIAyYAIAwAAREASIuzKqRHjsckwQALUrhMASAZEGAAAIAKSE2HBLTNiXMwWZ0r7sd6eqaxtZ5AXVadclgpSpW3aSNqqI53Zfs3PTma3N7Tz9wtgQtSuEwBIBkQYAAAgApIU4Vx3My298tOTVFnRcmzktpv1RFeWQ/Iq5badFWGn37KdLjeyrYt7ywCTpHadAEAyIMIAAAARkLQI+9usqLrl/ZbtzK6d3bXb3XpCuV6IdznzDDAlatcJACQDIgwAABABSYpwP2EdRIR1PTNL7Je7P83mSh8ahBimS+06AYBkQIQBAAAiID0Rdm+H7nNrtG0TWvb61O3ccm+72y7r2bPqtB2ZBpggtesEAJIBEQYAAIiAJERYz77aePJZ2W5maF2RbVjuOl+E1c6yUnQrP6WNUK7bmWDTDguGKVG7TgAgGRBhAACACIhehAGgBtcJQLogwgAAABGACAOkB9cJQLogwgAAABGACAOkB9cJQLogwgAAABGACAOkB9cJQLogwgAAABEQowgTQgghsxpEGAAAIAJiFGEA6A/XCUC6IMIAAAARgAgDpAfXCUC6IMIAAAARgAgDpAfXCUC6IMIAAAARgAgDpAfXCUC6IMIAAAAREL0IL3ZUu9VSLZ1MdSvrpsxUBTheqF0nAJAMiDAAAEAERC/Cgshvu6MW/WWhm6mWuw5wHBC8TgAgCRBhAACACEhehFVXZWZWeLHT7s0UI8cwwwSvEwBIAkQYAAAgAlIXYS2/si7lzm3S3YxbpmF2CV4nAJAEiDAAAEAEJCnC7meESymWmWEpQ4Bh9gleJwCQBIgwAABABCQpws6McB2EGGaf4HUCAEmACAMAAETAzIhwXp51bOmi6rTbqlwFmDGC1wkAJAEiDAAAEAHRi7CIb3krdFb8+aTgjLCdCS7SxoJhhqldJwCQDIgwAABABEQvwgBQg+sEIF0QYQAAgAhAhAHSg+sEIF0QYQAAgAhAhAHSg+sEIF0QYQAAgAhAhAHSg+sEIF0QYQAAgAiIUYQJIYSQWQ0iDAAAEAExijAA9IfrBCBdEGEAAIAIQIQB0oPrBCBdEGEAAIAIQIQB0oPrBCBdEGEAAIAIOC5EeLGj2u2OWjSrJU3l/VhJG4ARM5brBAAmAiIMAAAQAdGLsIhnq6XaHUc9B5FRt05T/ZVI7UraAIyY2nUCAMmACAMAAERAEiLczlTWbqvShQeRUbdOU/2VSO1K2gCMmNp1AgDJgAgDAABEQBoinItnN1OtrFsts8utlmrpWFleVJ22LWupdpbl9UWmvXqN/WTKjJTTVVlZ3lJZx2kj+2T6Wuy0yzotRBnGTO06AYBkQIQBAAAiIBkRzhe7WS6iYqhlmUiqI62+2LrLpSTLai6tsq3Sj+nbbi8G0kJtyzW2je7TjO0u53Rz8XabAIya2nUCAMmACAMAAERASiJckdBSRnuztUUcOfXbybKg2+X13H76bTfFGr3NGUdjZ40RYJgMtesEAJIBEQYAAIiApERYr7Z7tyeHRNXibvPraZldhQjnZd1y1tgFIYbJULtOACAZEGEAAIAISE2ES9nUZdVbmitYmbXLTh/lrc9l+Qpujc4X5VZt/W3WeVlm77vWbZwv9gIYA7XrBACSAREGAACIgPREOEe+pMqWyXY9C2vi1BVRlTL9ZVmhOm7flX6cGV2v/8qXZRmBbudlxUxwkcqfegIYA7XrBACSAREGAACIgOhFGABqcJ0ApAsiDAAAEAGIMEB6cJ0ApAsiDAAAEAGIMEB6cJ0ApAsiDAAAEAGIMEB6cJ0ApAsiDAAAEAExijAhhBAyq0GEAQAAImC1IgwAAACDgwgDAABEACIMAAAwORBhAACACECEAQAAJgciDAAAEAGIMAAAwORAhAEAACIAEQYAAJgciDAAAEAEIMIAAACTAxEGAACIAEQYAABgciDCAAAAEYAIAwAATA5EGAAAIAIQYQAAgMnR/3X3sPr/AbPMFn8ebE6PAAAAAElFTkSuQmCC)